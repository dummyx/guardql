#!/usr/bin/env ruby
# Aggregate GC-stress PoCs for missing-guard candidates.

require_relative "poc_utils"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

def case_enabled?(name)
  only = ENV["POC_CASES"]
  return true if only.nil? || only.empty?
  only.split(",").map(&:strip).include?(name)
end

def require_feature(feature)
  require feature
  true
rescue LoadError
  false
end

def pick_transcode_pair
  from = "UTF-8"
  targets = ["UTF-16LE", "UTF-16BE", "UTF-32LE", "UTF-32BE", "ISO-8859-1", "US-ASCII"]
  targets.each do |to|
    begin
      conv = Encoding::Converter.new(from, to)
      conv.finish
      return [from, to]
    rescue Encoding::ConverterNotFoundError
    ensure
      conv&.finish rescue nil
    end
  end
  nil
end

def static_rsa_key
  pem = <<~PEM
    -----BEGIN PRIVATE KEY-----
    MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAOTcqrcxFnlYRYSk
    w1ahaUnGuuUL4ZuGvP1pwqMI+u0CmbhNorSSejIgFsekCW/niW2cYg+frcxO+7Wd
    B19k6D6EUxQR8Qib4AC9/lMuHJSsywEGlHp9HMavhyjisnS/wit9wPn8bOI7U+0e
    Fu422oi67Y7ruP9+IbRgUe+4z3JjAgMBAAECgYAxL6/NAVLIL415TYPh6Xzca0ad
    lWkeaN3TRNic+4AaUhXBg4X1cwmqHjVnIL0afNOPaC23F+VdZJg6Vw5PlTtIVDAx
    Tv9u7Oio7qZI/Qe79CkSCpb4h6Eop5FpOCO1v+t+HvpTxFckyIuNZjoRBnFUX+36
    djRd+xkvI2pdkZOkcQJBAP7BDPW9i48Dcrk3FVSN8N8mR4JXnxEIizpo8OwiBvQN
    h69udQ747CA4vsZJhJa0sbmHP2Utj+pj5GHV30AAMvsCQQDl+zMXUQ+qKJ8dtf/w
    VgF2ff1DJspA9F2dLOPWacpCsgDyNeXO64RC1Nfnq4wc+EJmI6eLp7H2mCFx9jP8
    1OG5AkAqMQLaeCfy6ZlIf4zy0gdAjfBt7+ESSx3z8IlmMkSAivUb4ulUL3m75GoE
    IQzqgMameXXQZfld0mlyop801FOdAkA9+N7fnZxXAfM+kliRbtueDn08pytBLZg8
    Tmhm0sMKDeVrX1K524UcbTZw2y06cTuTQnBXlazDAmOgzfNcYhEhAkEAnENyRbG5
    4NhHEB3FxaEDBs0fiqwnadIY3mEuXZKW43ZMHAH9pDd74cT0rsOl03BWboBNejkl
    Cwqzo7MBgcJqqQ==
    -----END PRIVATE KEY-----
  PEM
  OpenSSL::PKey::RSA.new(pem)
end

class POCToStrLarge
  def initialize(size, fill = "b")
    @size = size
    @fill = fill
  end

  def to_str
    @fill * @size
  end
end

def run_case(name, seconds)
  return unless case_enabled?(name)
  puts "== case: #{name}"
  iterations = 0
  errors = 0
  POC.run_for(seconds) do
    begin
      yield(iterations)
      POC.maybe_alloc_junk(iterations)
    rescue Exception => e
      raise if e.is_a?(SystemExit) || e.is_a?(SignalException) || e.is_a?(NoMemoryError)
      errors += 1
      if errors <= 3
        warn "case #{name} error: #{e.class}: #{e.message}"
      end
    end
    iterations += 1
  end
  puts "== case: #{name} done iterations=#{iterations} errors=#{errors}"
end

def skip_case(name, reason)
  return unless case_enabled?(name)
  puts "== case: #{name} skipped (#{reason})"
end

case_seconds = (ENV["POC_CASE_SECONDS"] || "10").to_i

# Keep GC pressure high throughout all cases.
# This thread intentionally runs across cases.
gc_thread = POC.start_gc_hammer
alloc_thread = POC.start_alloc_hammer

begin
  # IO::Buffer cases
  io_buffer_available = IO.const_defined?(:Buffer)
  io_buffer_available ||= require_feature("io/buffer") && IO.const_defined?(:Buffer)
  if io_buffer_available
    run_case("io_buffer_for_make_instance", case_seconds) do |i|
      s = "a" * (512 + (i % 512))
      IO::Buffer.for(s)
    end

    run_case("io_buffer_set_string", case_seconds) do |i|
      size = 1024 * 1024
      buf ||= IO::Buffer.new(size)
      buf.set_string(POCToStrLarge.new(size, "b"))
    end
  else
    skip_case("io_buffer_for_make_instance", "missing io/buffer")
    skip_case("io_buffer_set_string", "missing io/buffer")
  end

  # Backtrace formatting
  run_case("location_format", case_seconds) do
    begin
      1.times do
        1.times do
          1.times do
            raise "boom"
          end
        end
      end
    rescue => e
      e.backtrace
      e.full_message
    end
  end

  # sprintf / formatting
  run_case("rb_enc_vsprintf", case_seconds) do |i|
    a = "a" * (1024 + (i % 1024))
    b = "b" * (1024 + ((i * 7) % 1024))
    sprintf("%s-%d-%s", a, i, b)
  end

  # NameError / inspect formatting
  run_case("name_err_mesg_to_str", case_seconds) do
    begin
      Object.const_get("MissingConst#{rand(1000)}")
    rescue NameError => e
      e.message
      e.inspect
    end
  end

  run_case("make_inspectname", case_seconds) do
    begin
      Object.send(:"missing_method_#{rand(1000)}")
    rescue NoMethodError => e
      e.inspect
    end
  end

  # Pack/unpack
  run_case("pack_pack", case_seconds) do |i|
    [i, i + 1, i + 2, i + 3].pack("L<*")
  end

  run_case("pack_unpack_internal", case_seconds) do |i|
    ("A" * 64 + i.to_s).unpack("H*")
  end

  run_case("qpencode", case_seconds) do
    ["a" * 200].pack("M")
  end

  # Enumerator / Enumerable
  run_case("enumerator_peek_values", case_seconds) do
    enum = [1, 2, 3].to_enum
    enum.peek_values
  end

  run_case("inspect_enumerator", case_seconds) do
    enum = [1, 2, 3].to_enum
    enum.inspect
  end

  run_case("append_method", case_seconds) do
    enum = [1, 2, 3].to_enum
    enum.inspect
  end

  run_case("inspect_enum_chain", case_seconds) do
    enum = [1, 2].each.chain([3, 4].each)
    enum.inspect
  end

  run_case("inspect_enum_product", case_seconds) do
    enum = Enumerator::Product.new([1, 2], [:a, :b])
    enum.inspect
  end

  run_case("generator_each", case_seconds) do
    gen = Enumerator::Generator.new { |y| y << 1; y << 2 }
    gen.each { |v| v }
  end

  run_case("arith_seq_inspect", case_seconds) do
    1.step(10, 2).inspect
  end

  run_case("chunk_ii", case_seconds) do
    "aabbcc".chars.chunk(&:itself).to_a
  end

  run_case("chunk_i", case_seconds) do
    "aabbcc".chars.chunk(&:itself).to_a
  end

  run_case("slicewhen_ii", case_seconds) do
    [1, 2, 3, 6, 7].slice_when { |a, b| b - a > 1 }.to_a
  end

  run_case("enum_zip", case_seconds) do
    [1, 2, 3].zip([4, 5, 6])
  end

  run_case("enum_minmax_by", case_seconds) do
    [1, 2, 3].minmax_by { |x| -x }
  end

  # Addrinfo / Socket
  if require_feature("socket")
    run_case("addrinfo_initialize", case_seconds) do
      Addrinfo.new(["AF_INET", 80, "localhost", "127.0.0.1"])
    end

    run_case("addrinfo_inspect", case_seconds) do
      Addrinfo.tcp("127.0.0.1", 80).inspect
    end

    run_case("rsock_getaddrinfo", case_seconds) do
      Socket.getaddrinfo("localhost", "http")
    end

    run_case("rb_scheduler_getaddrinfo", case_seconds) do
      if Fiber.respond_to?(:set_scheduler)
        scheduler = Class.new do
          def block(*); end
          def unblock(*); end
          def block_timeout(*); end
          def blocking_operation_wait(*); end
          def io_wait(*); end
          def kernel_sleep(*); end
          def process_wait(*); end
        end.new
        Fiber.set_scheduler(scheduler)
      end
      Socket.getaddrinfo("localhost", "http")
    end

    run_case("make_hostent_internal", case_seconds) do
      Socket.gethostbyname("localhost")
    end

    run_case("rsock_getifaddrs", case_seconds) do
      if Socket.respond_to?(:getifaddrs)
        begin
          Socket.getifaddrs
        rescue Errno::EPERM, Errno::EACCES
        end
      else
        raise "Socket.getifaddrs not available"
      end
    end

    run_case("rsock_init_unixsock", case_seconds) do
      require "tmpdir"
      Dir.mktmpdir do |dir|
        path = File.join(dir, "sock")
        begin
          server = UNIXServer.new(path)
        rescue Errno::EPERM, Errno::EACCES
          next
        end
        begin
          client = UNIXSocket.new(path)
          client.close
        rescue Errno::EPERM, Errno::EACCES
        end
        server.close
      end
    end

    skip_case("bsock_setsockopt", "socket creation blocked in sandbox")
    skip_case("sock_connect", "socket creation blocked in sandbox")

    run_case("sock_s_getservbyname", case_seconds) do
      Socket.getservbyname("http", "tcp")
    end

    run_case("rsock_read_nonblock", case_seconds) do
      a, b = Socket.pair(:UNIX, :STREAM, 0)
      begin
        a.write("a")
        b.read_nonblock(1)
      rescue IO::WaitReadable, IO::WaitWritable
      ensure
        a.close
        b.close
      end
    end

    run_case("rsock_write_nonblock", case_seconds) do
      a, b = Socket.pair(:UNIX, :STREAM, 0)
      begin
        a.write_nonblock("a")
      rescue IO::WaitWritable
      ensure
        a.close
        b.close
      end
    end

    if Socket.instance_methods.include?(:sendmsg)
      run_case("bsock_sendmsg_internal", case_seconds) do
        a, b = Socket.pair(:UNIX, :DGRAM, 0)
        begin
          a.sendmsg("hi")
          b.recvmsg
        ensure
          a.close
          b.close
        end
      end
    else
      skip_case("bsock_sendmsg_internal", "sendmsg not available")
    end
  else
    skip_case("addrinfo_initialize", "missing socket")
    skip_case("addrinfo_inspect", "missing socket")
    skip_case("rsock_getaddrinfo", "missing socket")
    skip_case("rb_scheduler_getaddrinfo", "missing socket")
    skip_case("make_hostent_internal", "missing socket")
    skip_case("rsock_getifaddrs", "missing socket")
    skip_case("rsock_init_unixsock", "missing socket")
    skip_case("bsock_setsockopt", "missing socket")
    skip_case("sock_connect", "missing socket")
    skip_case("sock_s_getservbyname", "missing socket")
    skip_case("rsock_read_nonblock", "missing socket")
    skip_case("rsock_write_nonblock", "missing socket")
    skip_case("bsock_sendmsg_internal", "missing socket")
  end

  # String crypt
  run_case("rb_str_crypt", case_seconds) do |i|
    ("password" + i.to_s).crypt("aa")
  end

  # Date parsing
  if require_feature("date")
    run_case("s3e", case_seconds) do
      Date._parse("Tue, 2024-07-05 12:34:56 +0000")
    end

    run_case("date_s__strptime_internal", case_seconds) do
      Date._strptime("2024-07-05 12:34:56", "%Y-%m-%d %H:%M:%S")
    end

    run_case("parse_us_cb", case_seconds) do
      Date._parse("12/31/2024")
    end

    run_case("parse_eu_cb", case_seconds) do
      Date._parse("31/12/2024")
    end

    run_case("date_strftime_internal", case_seconds) do
      Date.today.strftime("%Y-%m-%d")
    end

    run_case("date_strftime_with_tmx", case_seconds) do
      Date.today.strftime("%F %T %z")
    end

    run_case("deconstruct_keys", case_seconds) do
      Date.today.deconstruct_keys(nil)
    end

    run_case("rt_complete_frags", case_seconds) do
      Date._strptime("2024-07-05 12:34:56 +0000", "%Y-%m-%d %H:%M:%S %z")
    end
  else
    skip_case("s3e", "missing date")
    skip_case("date_s__strptime_internal", "missing date")
    skip_case("parse_us_cb", "missing date")
    skip_case("parse_eu_cb", "missing date")
    skip_case("date_strftime_internal", "missing date")
    skip_case("date_strftime_with_tmx", "missing date")
    skip_case("deconstruct_keys", "missing date")
    skip_case("rt_complete_frags", "missing date")
  end

  # ObjectSpace
  if require_feature("objspace")
    run_case("newobj_i", case_seconds) do |i|
      ObjectSpace.trace_object_allocations do
        Object.new
        "x" * (i % 256)
      end
    end

    if ObjectSpace.respond_to?(:dump)
      run_case("dump_object", case_seconds) do
        ObjectSpace.dump(Object.new)
      end
    else
      skip_case("dump_object", "ObjectSpace.dump not available")
    end
  else
    skip_case("newobj_i", "missing objspace")
    skip_case("dump_object", "missing objspace")
  end

  # Thread / TracePoint / Proc
  run_case("rb_thread_to_s", case_seconds) do
    Thread.current.to_s
  end

  run_case("thread_do_start_proc", case_seconds) do |i|
    args = Array.new(10) { "x" * (128 + (i % 128)) }
    t = Thread.new(*args) { |*xs| xs.length }
    t.join
  end

  run_case("proc_binding", case_seconds) do
    x = rand(1000)
    pr = proc { x }
    b = pr.binding
    b.local_variable_get(:x)
  end

  run_case("rb_tracepoint_enable_for_target", case_seconds) do
    tp = TracePoint.new(:call) { }
    begin
      tp.enable(target: Thread.current) do
        "tracepoint".to_s
      end
    rescue ArgumentError
    end
  end

  run_case("rb_proc_compose_to_left", case_seconds) do
    f = ->(x) { x + 1 }
    g = ->(x) { x * 2 }
    (f << g).call(3)
  end

  # -test- extensions
  if require_feature("-test-/bignum")
    run_case("rb_integer_unpack_m", case_seconds) do
      flags = Bug::Bignum::INTEGER_PACK_LSWORD_FIRST | Bug::Bignum::INTEGER_PACK_LSBYTE_FIRST
      Bug::Bignum.test_unpack("\x01\x02\x03\x04", 1, 4, 0, flags)
    end
  else
    skip_case("rb_integer_unpack_m", "missing -test-/bignum")
  end

  if require_feature("-test-/load/stringify_symbols")
    run_case("stringify_symbol", case_seconds) do
      lib = File.expand_path("../../ruby/build-o3/.ext/x86_64-linux/-test-/load/stringify_target.so", __dir__)
      StringifySymbols.stringify_symbol(lib, "Init_stringify_target")
    end
  else
    skip_case("stringify_symbol", "missing -test-/load/stringify_symbols")
  end

  if require_feature("-test-/memory_view")
    run_case("memory_view_extract_item_members", case_seconds) do
      str = [1, 2].pack("II")
      MemoryViewTestUtils.extract_item_members(str, "II")
    end

    run_case("memory_view_parse_item_format", case_seconds) do
      MemoryViewTestUtils.parse_item_format("II")
    end
  else
    skip_case("memory_view_extract_item_members", "missing -test-/memory_view")
    skip_case("memory_view_parse_item_format", "missing -test-/memory_view")
  end

  if require_feature("-test-/string")
    run_case("bug_str_cstr_term", case_seconds) do
      Bug::String.new("abc").cstr_term
    end

    run_case("bug_rb_define_dummy_encoding", case_seconds) do |i|
      if i < 32
        Bug::String.rb_define_dummy_encoding("X-POC-ENC-#{i}")
      end
    end
  else
    skip_case("bug_str_cstr_term", "missing -test-/string")
    skip_case("bug_rb_define_dummy_encoding", "missing -test-/string")
  end

  if require_feature("-test-/struct")
    run_case("bug_struct_new_duplicate", case_seconds) do
      begin
        Bug::Struct.new_duplicate("S", "a")
      rescue ArgumentError
      end
    end

    run_case("bug_struct_new_duplicate_under", case_seconds) do
      begin
        Bug::Struct.new_duplicate_under("S", "a")
      rescue ArgumentError
      end
    end
  else
    skip_case("bug_struct_new_duplicate", "missing -test-/struct")
    skip_case("bug_struct_new_duplicate_under", "missing -test-/struct")
  end

  if require_feature("-test-/symbol")
    run_case("sym_iv_get", case_seconds) do
      obj = Object.new
      obj.instance_variable_set(:@bar, 1)
      Bug::Symbol.iv_get(obj, "@bar")
    end
  else
    skip_case("sym_iv_get", "missing -test-/symbol")
  end

  # Digest bubblebabble
  if require_feature("digest/bubblebabble")
    run_case("bubblebabble_str_new", case_seconds) do
      Digest.bubblebabble("data")
    end
  else
    skip_case("bubblebabble_str_new", "missing digest/bubblebabble")
  end

  # Etc
  if require_feature("etc")
    run_case("etc_getpwnam", case_seconds) do
      Etc.getpwnam("root")
    end

    run_case("etc_getgrnam", case_seconds) do
      Etc.getgrnam("root")
    end
  else
    skip_case("etc_getpwnam", "missing etc")
    skip_case("etc_getgrnam", "missing etc")
  end

  # Fiddle
  if require_feature("fiddle")
    unless Fiddle.respond_to?(:last_error=)
      Fiddle.singleton_class.define_method(:last_error=) { |_val| }
    end
    unless Fiddle.respond_to?(:last_error)
      Fiddle.singleton_class.define_method(:last_error) { 0 }
    end
    run_case("fiddle_handle_find_func", case_seconds) do
      Fiddle::Handle::DEFAULT["malloc"]
    end

    run_case("function_call", case_seconds) do
      func = Fiddle::Function.new(
        Fiddle::Handle::DEFAULT["strlen"],
        [Fiddle::Types::VOIDP],
        Fiddle::Types::SIZE_T
      )
      func.call("abcdef")
    end

    run_case("normalize_argument_types", case_seconds) do
      func = Fiddle::Function.new(
        Fiddle::Handle::DEFAULT["strlen"],
        [Fiddle::Types::VOIDP],
        Fiddle::Types::SIZE_T
      )
      func.call("abcdef")
    end

    run_case("initialize_body", case_seconds) do
      closure_class = Class.new(Fiddle::Closure) do
        def call(*)
          10
        end
      end
      closure = closure_class.new(Fiddle::Types::INT, [])
      func = Fiddle::Function.new(closure, [], Fiddle::Types::INT)
      func.call
    end
  else
    skip_case("fiddle_handle_find_func", "missing fiddle")
    skip_case("function_call", "missing fiddle")
    skip_case("normalize_argument_types", "missing fiddle")
    skip_case("initialize_body", "missing fiddle")
  end

  # Psych
  if require_feature("psych")
    run_case("start_document_try", case_seconds) do
      Psych.dump({ "a" => 1 })
    end
  else
    skip_case("start_document_try", "missing psych")
  end

  # OpenSSL
  if require_feature("openssl")
    run_case("ossl_cipher_initialize", case_seconds) do
      OpenSSL::Cipher.new("AES-128-CBC")
    end

    run_case("ossl_cipher_pkcs5_keyivgen", case_seconds) do
      c = OpenSSL::Cipher.new("AES-128-CBC")
      c.pkcs5_keyivgen("password", "12345678", 1, "md5")
    end

    run_case("ossl_cipher_update", case_seconds) do
      c = OpenSSL::Cipher.new("AES-128-CBC")
      c.encrypt
      c.key = "k" * 16
      c.iv = "i" * 16
      c.update("a" * 1024)
    end

    run_case("ossl_provider_s_load", case_seconds) do
      if OpenSSL.const_defined?(:Provider)
        OpenSSL::Provider.load("default")
      else
        raise "OpenSSL::Provider not available"
      end
    end

    run_case("ossl_x509store_add_file", case_seconds) do
      store = OpenSSL::X509::Store.new
      cert_file = OpenSSL::X509::DEFAULT_CERT_FILE
      store.add_file(cert_file) if cert_file && File.exist?(cert_file)
    end

    run_case("ossl_x509store_add_path", case_seconds) do
      store = OpenSSL::X509::Store.new
      cert_dir = OpenSSL::X509::DEFAULT_CERT_DIR
      store.add_path(cert_dir) if cert_dir && Dir.exist?(cert_dir)
    end

    run_case("ossl_x509extfactory_create_ext", case_seconds) do
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.create_ext("basicConstraints", "CA:FALSE", true)
    end

    run_case("ssl_npn_encode_protocol_i", case_seconds) do
      if OpenSSL::SSL::SSLContext.instance_methods.include?(:npn_protocols=)
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.npn_protocols = ["http/1.1", "spdy/3"]
      else
        raise "npn_protocols= not available"
      end
    end

    run_case("ossl_ec_point_mul", case_seconds) do
      group = OpenSSL::PKey::EC::Group.new("prime256v1")
      point = group.generator
      point.mul(2)
    end

    run_case("ossl_ec_point_add", case_seconds) do
      group = OpenSSL::PKey::EC::Group.new("prime256v1")
      point = group.generator
      point.add(point)
    end

    run_case("ossl_ec_point_initialize_copy", case_seconds) do
      group = OpenSSL::PKey::EC::Group.new("prime256v1")
      point = group.generator
      point.dup
    end

    run_case("ossl_ocspbres_add_status", case_seconds) do
      key = static_rsa_key
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 1
      name = OpenSSL::X509::Name.new([["CN", "ocsp"]])
      cert.subject = name
      cert.issuer = name
      cert.public_key = key
      cert.not_before = Time.now
      cert.not_after = Time.now + 3600
      cert.sign(key, OpenSSL::Digest.new("SHA256"))

      cid = OpenSSL::OCSP::CertificateId.new(cert, cert, OpenSSL::Digest.new("SHA1"))
      bres = OpenSSL::OCSP::BasicResponse.new
      bres.add_status(
        cid,
        OpenSSL::OCSP::V_CERTSTATUS_GOOD,
        nil,
        nil,
        Time.now,
        Time.now + 3600,
        nil
      )
    end

    run_case("ossl_evp_md_fetch_i", case_seconds) do
      key = static_rsa_key
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 2
      name = OpenSSL::X509::Name.new([["CN", "tsa"]])
      cert.subject = name
      cert.issuer = name
      cert.public_key = key
      cert.not_before = Time.now
      cert.not_after = Time.now + 3600
      cert.sign(key, OpenSSL::Digest.new("SHA256"))

      req = OpenSSL::Timestamp::Request.new
      req.algorithm = "SHA256"
      req.message_imprint = OpenSSL::Digest.new("SHA256").digest("data")
      req.policy_id = "1.2.3.4.5"

      fac = OpenSSL::Timestamp::Factory.new
      fac.serial_number = 1
      fac.gen_time = Time.now
      fac.allowed_digests = ["SHA256", "SHA1"]
      fac.default_policy_id = "1.2.3.4.5"
      fac.create_timestamp(key, cert, req)
    end

    run_case("ossl_tsfac_create_ts", case_seconds) do
      key = static_rsa_key
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = 2
      name = OpenSSL::X509::Name.new([["CN", "tsa"]])
      cert.subject = name
      cert.issuer = name
      cert.public_key = key
      cert.not_before = Time.now
      cert.not_after = Time.now + 3600
      ext = OpenSSL::X509::ExtensionFactory.new
      ext.subject_certificate = cert
      ext.issuer_certificate = cert
      cert.add_extension(ext.create_ext("basicConstraints", "CA:FALSE", true))
      cert.add_extension(ext.create_ext("keyUsage", "digitalSignature", true))
      cert.add_extension(ext.create_ext("extendedKeyUsage", "timeStamping", true))
      cert.add_extension(ext.create_ext("subjectKeyIdentifier", "hash"))
      cert.add_extension(ext.create_ext("authorityKeyIdentifier", "keyid:always"))
      cert.sign(key, OpenSSL::Digest.new("SHA256"))

      req = OpenSSL::Timestamp::Request.new
      req.algorithm = "SHA256"
      req.message_imprint = OpenSSL::Digest.new("SHA256").digest("data")
      req.policy_id = "1.2.3.4.5"

      fac = OpenSSL::Timestamp::Factory.new
      fac.serial_number = 1
      fac.gen_time = Time.now
      fac.allowed_digests = ["SHA256"]
      fac.default_policy_id = "1.2.3.4.5"
      fac.create_timestamp(key, cert, req)
    end

    run_case("ossl_ssl_write_internal", case_seconds) do
      require "socket"

      a, b = Socket.pair(:UNIX, :STREAM, 0)
      begin
        key = static_rsa_key
        cert = OpenSSL::X509::Certificate.new
        cert.version = 2
        cert.serial = 3
        name = OpenSSL::X509::Name.new([["CN", "localhost"]])
        cert.subject = name
        cert.issuer = name
        cert.public_key = key
        cert.not_before = Time.now
        cert.not_after = Time.now + 3600
        cert.sign(key, OpenSSL::Digest.new("SHA256"))

        ctx_server = OpenSSL::SSL::SSLContext.new
        ctx_server.cert = cert
        ctx_server.key = key
        ctx_server.security_level = 0 if ctx_server.respond_to?(:security_level=)
        ctx_server.verify_mode = OpenSSL::SSL::VERIFY_NONE

        ctx_client = OpenSSL::SSL::SSLContext.new
        ctx_client.security_level = 0 if ctx_client.respond_to?(:security_level=)
        ctx_client.verify_mode = OpenSSL::SSL::VERIFY_NONE

        server = OpenSSL::SSL::SSLSocket.new(a, ctx_server)
        client = OpenSSL::SSL::SSLSocket.new(b, ctx_client)
        server.sync_close = true if server.respond_to?(:sync_close=)
        client.sync_close = true if client.respond_to?(:sync_close=)

        t = Thread.new { server.accept }
        client.connect
        t.join

        client.syswrite("a" * 1024)
        client.close if client.respond_to?(:close)
        server.close if server.respond_to?(:close)
      ensure
        a.close rescue nil
        b.close rescue nil
      end
    end
  else
    skip_case("ossl_cipher_initialize", "missing openssl")
    skip_case("ossl_cipher_pkcs5_keyivgen", "missing openssl")
    skip_case("ossl_cipher_update", "missing openssl")
    skip_case("ossl_provider_s_load", "missing openssl")
    skip_case("ossl_x509store_add_file", "missing openssl")
    skip_case("ossl_x509store_add_path", "missing openssl")
    skip_case("ossl_x509extfactory_create_ext", "missing openssl")
    skip_case("ssl_npn_encode_protocol_i", "missing openssl")
    skip_case("ossl_ec_point_mul", "missing openssl")
    skip_case("ossl_ec_point_add", "missing openssl")
    skip_case("ossl_ec_point_initialize_copy", "missing openssl")
    skip_case("ossl_ocspbres_add_status", "missing openssl")
    skip_case("ossl_tsfac_create_ts", "missing openssl")
    skip_case("ossl_ssl_write_internal", "missing openssl")
  end

  # Zlib
  if require_feature("zlib")
    require "stringio"
    run_case("rb_deflate_deflate", case_seconds) do
      Zlib::Deflate.deflate("a" * 1024)
    end

    run_case("do_deflate", case_seconds) do
      Zlib::Deflate.deflate("b" * 1024)
    end

    run_case("do_inflate", case_seconds) do
      data = Zlib::Deflate.deflate("a" * 1024)
      Zlib::Inflate.inflate(data)
    end

    run_case("rb_deflate_flush", case_seconds) do
      d = Zlib::Deflate.new
      d << ("a" * 1024)
      d.flush
      d.finish
    end

    run_case("rb_deflate_init_copy", case_seconds) do
      d = Zlib::Deflate.new
      d.deflate("a" * 128)
      d.dup
      d.finish
    end

    run_case("rb_zstream_finish", case_seconds) do
      d = Zlib::Deflate.new
      d.deflate("a" * 128)
      d.finish
    end

    run_case("rb_gzwriter_write", case_seconds) do
      io = StringIO.new
      gz = Zlib::GzipWriter.new(io)
      gz.write("a" * 1024)
      gz.close
    end

    run_case("rb_gzfile_set_comment", case_seconds) do
      io = StringIO.new
      gz = Zlib::GzipWriter.new(io)
      gz.comment = "comment"
      gz.write("a" * 256)
      gz.close
    end

    run_case("rb_gzfile_set_orig_name", case_seconds) do
      io = StringIO.new
      gz = Zlib::GzipWriter.new(io)
      gz.orig_name = "orig.txt"
      gz.write("a" * 256)
      gz.close
    end

    run_case("rb_gzreader_read", case_seconds) do
      io = StringIO.new
      gz = Zlib::GzipWriter.new(io)
      gz.write("a" * 1024)
      gz.finish
      io.rewind
      reader = Zlib::GzipReader.new(io)
      reader.read(128)
      reader.close
    end

    run_case("rb_gzreader_readpartial", case_seconds) do
      io = StringIO.new
      gz = Zlib::GzipWriter.new(io)
      gz.write("a" * 1024)
      gz.finish
      io.rewind
      reader = Zlib::GzipReader.new(io)
      reader.readpartial(64)
      reader.close
    end

    run_case("gzreader_gets", case_seconds) do
      io = StringIO.new
      gz = Zlib::GzipWriter.new(io)
      gz.write("a\nb\nc\n")
      gz.finish
      io.rewind
      reader = Zlib::GzipReader.new(io)
      reader.gets
      reader.close
    end

    run_case("gzfile_getc", case_seconds) do
      dummy_name = "X-POC-GZ-DUMMY"
      dummy = (Encoding.find(dummy_name) rescue nil)
      unless dummy
        if require_feature("-test-/string") && defined?(Bug::String) && Bug::String.respond_to?(:rb_define_dummy_encoding)
          Bug::String.rb_define_dummy_encoding(dummy_name)
          dummy = (Encoding.find(dummy_name) rescue nil)
        end
      end

      io = StringIO.new
      gz = Zlib::GzipWriter.new(io)
      gz.write("a" * 1024)
      gz.finish
      io.rewind
      opts = {}
      if dummy
        opts = { external_encoding: dummy, internal_encoding: Encoding.find("UTF-8") }
      end
      reader = if opts.empty?
                 Zlib::GzipReader.new(io)
               else
                 Zlib::GzipReader.new(io, **opts)
               end
      reader.getc
      reader.close
    end

    run_case("rb_gzreader_ungetc", case_seconds) do
      io = StringIO.new
      gz = Zlib::GzipWriter.new(io)
      gz.write("a" * 1024)
      gz.finish
      io.rewind
      reader = Zlib::GzipReader.new(io, encoding: "UTF-16LE")
      reader.ungetc("b" * 32)
      reader.close
    end

    run_case("rb_gzreader_s_zcat", case_seconds) do
      require "stringio"
      io = StringIO.new
      gz = Zlib::GzipWriter.new(io)
      gz.write("a" * 16_384)
      gz.finish
      data_io = StringIO.new(io.string)
      Zlib::GzipReader.zcat(data_io)
    end

    run_case("rb_inflate_sync", case_seconds) do
      infl = Zlib::Inflate.new
      begin
        infl.inflate("\x00\x01\x02")
      rescue Zlib::DataError
      end
      infl.sync("\x00\x00\xff\xff")
    ensure
      infl.close if infl
    end
  else
    skip_case("rb_deflate_deflate", "missing zlib")
    skip_case("do_deflate", "missing zlib")
    skip_case("do_inflate", "missing zlib")
    skip_case("rb_deflate_params", "missing zlib")
    skip_case("rb_deflate_flush", "missing zlib")
    skip_case("rb_deflate_init_copy", "missing zlib")
    skip_case("rb_zstream_finish", "missing zlib")
    skip_case("rb_gzwriter_write", "missing zlib")
    skip_case("rb_gzfile_set_comment", "missing zlib")
    skip_case("rb_gzfile_set_orig_name", "missing zlib")
    skip_case("rb_gzreader_read", "missing zlib")
    skip_case("rb_gzreader_readpartial", "missing zlib")
    skip_case("gzreader_gets", "missing zlib")
    skip_case("rb_gzreader_ungetc", "missing zlib")
    skip_case("rb_gzreader_s_zcat", "missing zlib")
    skip_case("rb_inflate_sync", "missing zlib")
  end

  # File / Dir
  run_case("rb_io_getline_1", case_seconds) do |i|
    r, w = IO.pipe
    begin
      w.write("line#{i}\n")
      w.close
      r.gets
    ensure
      r.close rescue nil
      w.close rescue nil
    end
  end

  run_case("appendline", case_seconds) do |i|
    r, w = IO.pipe
    begin
      w.write(("a" * 1024) + "\n" + ("b" * 1024) + "\n")
      w.close
      r.gets("\n")
    ensure
      r.close rescue nil
      w.close rescue nil
    end
  end

  run_case("path_sub_ext", case_seconds) do
    require "pathname"
    Pathname.new("foo.txt").sub_ext(".rb")
  end

  run_case("path_s_glob", case_seconds) do
    require "pathname"
    require "tmpdir"
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, "a.rb"), "x = 1\n")
      File.write(File.join(dir, "b.txt"), "x = 1\n")
      Pathname.glob(File.join(dir, "*")).map(&:to_s)
    end
  end

  run_case("path_glob", case_seconds) do
    require "pathname"
    require "tmpdir"
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, "a.rb"), "x = 1\n")
      File.write(File.join(dir, "b.txt"), "x = 1\n")
      Pathname.new(dir).glob("*.rb").map(&:to_s)
    end
  end

  run_case("rb_file_join", case_seconds) do |i|
    File.join("a", "b", i.to_s, "c")
  end

  run_case("append_fspath", case_seconds) do
    File.expand_path("../#{rand(1000)}")
  end

  run_case("rb_default_home_dir", case_seconds) do
    Dir.home
  end

  run_case("rb_home_dir_of", case_seconds) do
    Dir.home("root")
  end

  run_case("rb_getpwdirnam_for_login", case_seconds) do
    File.expand_path("~root")
  end

  run_case("realpath_rec", case_seconds) do
    File.realpath(".")
  end

  run_case("rb_check_realpath_emulate", case_seconds) do
    File.realdirpath(".././.", Dir.pwd)
  end

  run_case("rb_file_s_extname", case_seconds) do
    File.extname("foo.bar")
  end

  run_case("rb_file_lstat", case_seconds) do
    File.lstat(__FILE__)
  end

  run_case("rb_file_chown", case_seconds) do
    begin
      File.chown(Process.uid, Process.gid, __FILE__)
    rescue Errno::EPERM, Errno::ENOSYS
    end
  end

  run_case("chdir_path", case_seconds) do
    Dir.chdir(Dir.pwd) { }
  end

  run_case("dir_chdir0", case_seconds) do
    Dir.chdir(".")
  end

  run_case("dir_s_rmdir", case_seconds) do
    require "tmpdir"
    Dir.mktmpdir do |dir|
      empty = File.join(dir, "empty")
      Dir.mkdir(empty)
      Dir.rmdir(empty)
    end
  end

  run_case("dir_s_mkdir", case_seconds) do
    require "tmpdir"
    Dir.mktmpdir do |dir|
      target = File.join(dir, "created")
      Dir.mkdir(target)
    end
  end

  run_case("push_glob", case_seconds) do
    Dir.glob("*.rb")
  end

  run_case("argf_next_argv", case_seconds) do
    require "tmpdir"
    orig_argv = ARGV.dup
    Dir.mktmpdir do |dir|
      f1 = File.join(dir, "a.txt")
      f2 = File.join(dir, "b.txt")
      File.write(f1, "a\n")
      File.write(f2, "b\n")
      ARGV.replace([f1, f2])
      ARGF.each_line { |line| line }
    end
  ensure
    ARGV.replace(orig_argv)
  end

  skip_case("dir_s_chroot", "requires root")

  # ENV / Hash
  run_case("rb_env_clear", case_seconds) do
    backup = ENV.to_h
    ENV["A"] = "1"
    ENV["B"] = "2"
    ENV.clear
    backup.each { |k, v| ENV[k] = v }
  end

  run_case("symbol_key_needs_quote", case_seconds) do
    { :"a b" => 1, :"a-b" => 2 }.inspect
  end

  # IO core
  run_case("setup_narg", case_seconds) do
    r, w = IO.pipe
    begin
      if r.respond_to?(:ioctl)
        r.ioctl(0, "abc")
      elsif r.respond_to?(:fcntl)
        require "fcntl"
        r.fcntl(Fcntl::F_GETFD, "abc")
      end
    rescue StandardError
    ensure
      r.close
      w.close
    end
  end

  run_case("select_internal", case_seconds) do
    r, w = IO.pipe
    IO.select([r], [w], [], 0)
    r.close
    w.close
  end

  run_case("io_getpartial", case_seconds) do
    r, w = IO.pipe
    w.write("abc")
    w.close
    r.readpartial(2)
    r.close
  end

  run_case("io_read_nonblock", case_seconds) do
    r, w = IO.pipe
    w.write("a")
    w.close
    begin
      r.read_nonblock(1)
    rescue IO::WaitReadable
    ensure
      r.close
    end
  end

  run_case("io_write_nonblock", case_seconds) do
    r, w = IO.pipe
    begin
      w.write_nonblock("a")
    rescue IO::WaitWritable
    ensure
      r.close
      w.close
    end
  end

  if IO.instance_methods.include?(:pread)
    run_case("rb_io_pread", case_seconds) do
      File.open(__FILE__, "rb") do |io|
        io.pread(16, 0)
      end
    end
  else
    skip_case("rb_io_pread", "pread not available")
  end

  run_case("rb_io_getbyte", case_seconds) do
    File.open(__FILE__, "rb") do |io|
      io.getbyte
    end
  end

  # IO encoding
  run_case("check_pipe_command", case_seconds) do
    IO.popen("echo test", "r") { |io| io.read }
  end

  run_case("io_encoding_set", case_seconds) do
    r, w = IO.pipe
    r.set_encoding("UTF-8")
    r.close
    w.close
  end

  run_case("rb_io_extract_encoding_option", case_seconds) do
    require "tempfile"
    Tempfile.create("poc") do |f|
      f.write("hello")
      f.flush
      IO.read(f.path, encoding: "UTF-8")
    end
  end

  run_case("rb_str_end_with_asciichar", case_seconds) do
    ("abc" + rand(1000).to_s).end_with?("c")
  end

  # require / feature
  feature_libs = ["set", "pp", "pathname", "json"].select { |lib| require_feature(lib) }
  run_case("features_index_add", case_seconds) do |i|
    if (i % 10).zero?
      $LOADED_FEATURES << "poc_feature_#{i}.rb"
    end
    require "set"
  end

  run_case("rb_feature_p", case_seconds) do |i|
    if feature_libs.empty?
      raise LoadError, "no feature libs available"
    end
    require feature_libs[i % feature_libs.length]
  end

  run_case("rb_construct_expanded_load_path", case_seconds) do
    require "tmpdir"
    Dir.mktmpdir do |dir|
      feature = "poc_loadpath_#{rand(1_000_000)}"
      File.write(File.join(dir, "#{feature}.rb"), "PocLoadpathConst = 1\n")
      $LOAD_PATH.unshift(dir)
      begin
        require feature
      ensure
        $LOAD_PATH.shift
      end
    end
  end

  run_case("search_required", case_seconds) do |i|
    begin
      require "missing_feature_#{i}"
    rescue LoadError
    end
  end

  run_case("rb_warn_m", case_seconds) do |i|
    warn("poc warning #{i}")
  end

  if require_feature("ripper")
    if Ripper.respond_to?(:lex)
      run_case("rb_parser_lex_get_str", case_seconds) do
        Ripper.lex("a = 1\n")
      end
    else
      skip_case("rb_parser_lex_get_str", "Ripper.lex not available")
    end
  else
    skip_case("rb_parser_lex_get_str", "missing ripper")
  end

  run_case("parser_magic_comment", case_seconds) do
    require "tempfile"
    Tempfile.create(["poc_magic", ".rb"]) do |f|
      f.write("# encoding: UTF-8\nx = 1\n")
      f.flush
      if defined?(RubyVM::InstructionSequence)
        RubyVM::InstructionSequence.compile_file(f.path)
      else
        load f.path
      end
    end
  end

  # Marshal
  run_case("w_object", case_seconds) do
    Marshal.dump([:a, { b: 1 }, "x" * 128])
  end

  run_case("w_symbol", case_seconds) do
    Marshal.dump(:sym)
  end

  run_case("rand_mt_dump", case_seconds) do
    Marshal.dump(Random.new(1234))
  end

  run_case("r_bytes1_buffered", case_seconds) do
    Marshal.load(Marshal.dump("a" * 1024))
  end

  # Prism
  if require_feature("prism")
  run_case("pack_parse", case_seconds) do
      Prism::Pack.parse(:v3_2_0, :pack, "C*")
    end
  run_case("pm_ast_new", case_seconds) do
      Prism.parse("b = 3 + 4")
    end
  run_case("extract_options", case_seconds) do
      Prism.parse("a = 1", filepath: "poc.rb", line: 1)
    end
  else
    skip_case("pack_parse", "missing prism")
    skip_case("pm_ast_new", "missing prism")
    skip_case("extract_options", "missing prism")
  end

  # Process
  ruby_bin =
    begin
      ENV["POC_RUBY"] || (require "rbconfig"; RbConfig.ruby)
    rescue LoadError
      ENV["POC_RUBY"] || File.expand_path("../../ruby/build-o3/ruby", __dir__)
    end
  run_case("fill_envp_buf_i", case_seconds) do
    pid = Process.spawn({ "A" => "1" }, ruby_bin, "-e", "exit")
    Process.wait(pid)
  end

  run_case("rb_exec_fillarg", case_seconds) do
    pid = Process.spawn(ruby_bin, "-e", "exit")
    Process.wait(pid)
  end

  run_case("rb_execarg_parent_start1", case_seconds) do
    pid = Process.spawn(ruby_bin, "-e", "exit")
    Process.wait(pid)
  end

  run_case("process_sflag", case_seconds) do
    pid = Process.spawn(ruby_bin, "-s", "-e", "exit", "--", "-foo=bar")
    Process.wait(pid)
  end

  run_case("moreswitches", case_seconds) do
    pid = Process.spawn({ "RUBYOPT" => "-W2 -s" }, ruby_bin, "-e", "exit", "--", "-foo=bar")
    Process.wait(pid)
  end

  run_case("obj2uid", case_seconds) do
    Process::UID.from_name("root") if Process::UID.respond_to?(:from_name)
  end

  run_case("obj2gid", case_seconds) do
    Process::GID.from_name("root") if Process::GID.respond_to?(:from_name)
  end

  # String APIs
  run_case("deleted_prefix_length", case_seconds) do
    ("prefix" + rand(1000).to_s).delete_prefix("pre")
  end

  run_case("rb_str_slice_bang", case_seconds) do
    s = "abcdef"
    s.slice!(2, 2)
  end

  run_case("rb_str_downcase", case_seconds) do
    ("AbC" * 8).downcase
  end

  run_case("rb_str_upcase", case_seconds) do
    ("aBc" * 8).upcase
  end

  run_case("rb_str_s_new", case_seconds) do |i|
    orig = "a" * (128 + (i % 256))
    enc = (i % 2).zero? ? Encoding::UTF_8 : "UTF-8"
    String.new(orig, encoding: enc, capacity: 1024 + (i % 1024))
  end

  run_case("str_replace_shared_without_enc", case_seconds) do
    s = "abc"
    t = s.dup
    t.replace("def")
  end

  run_case("enc_str_scrub", case_seconds) do
    "a\xff".force_encoding("UTF-8").scrub
  end

  run_case("rb_reg_prepare_re", case_seconds) do
    /a.+b/ =~ "axxb"
  end

  run_case("rb_reg_preprocess_dregexp", case_seconds) do
    s = "ab"
    /#{s}/ =~ "ab"
  end

  run_case("rb_reg_regsub", case_seconds) do
    "ab12cd".sub(/(\\d+)/, "<\\1>")
  end

  run_case("match_array", case_seconds) do
    /a(.)/.match("ab").to_a
  end

  run_case("match_deconstruct_keys", case_seconds) do
    m = /(?<hours>\d+):(?<minutes>\d+)/.match("12:34")
    m.deconstruct_keys(nil)
  end

  run_case("rb_str_count", case_seconds) do
    ("abcdef" * 16).count("a-f")
  end

  run_case("rb_str_each_grapheme_cluster_size", case_seconds) do
    if "a".respond_to?(:each_grapheme_cluster)
      "a\u0301".each_grapheme_cluster { |gc| gc.size }
    else
      raise "each_grapheme_cluster not available"
    end
  end

  run_case("rb_str_enumerate_lines", case_seconds) do
    "a\nb\nc\n".lines.to_a
  end

  run_case("rb_str_escape", case_seconds) do
    ("a\n\tb" * 16).dump
  end

  run_case("rb_str_inspect", case_seconds) do
    ("a\n\tb" * 16).inspect
  end

  run_case("rb_str_fill_terminator", case_seconds) do
    s = "a" * 32
    s << "b" * 32
    s
  end

  run_case("rb_string_value_cstr", case_seconds) do
    File.basename("/tmp/test#{rand(1000)}")
  end

  run_case("str_null_check", case_seconds) do
    begin
      File.open("a\0b")
    rescue ArgumentError
    end
  end

  transcode_pair = pick_transcode_pair
  if transcode_pair
    from_enc, to_enc = transcode_pair
    run_case("str_transcode0", case_seconds) do
      ("a" * 256).encode(to_enc, from_enc, invalid: :replace, undef: :replace)
    end

    run_case("rb_econv_init_by_convpath", case_seconds) do
      conv = Encoding::Converter.new(from_enc, to_enc)
      conv.convert("a" * 128)
      conv.finish
    ensure
      conv&.finish rescue nil
    end

    run_case("econv_insert_output", case_seconds) do
      conv = Encoding::Converter.new(from_enc, to_enc)
      conv.insert_output("x" * 128)
      conv.convert("a" * 128)
      conv.finish
    ensure
      conv&.finish rescue nil
    end
  else
    skip_case("str_transcode0", "no transcode pair available")
    skip_case("rb_econv_init_by_convpath", "no transcode pair available")
    skip_case("econv_insert_output", "no transcode pair available")
  end

  # Autoload / const path
  run_case("check_autoload_required", case_seconds) do
    require "tempfile"
    Tempfile.create(["poc_autoload", ".rb"]) do |f|
      const_name = "TempConst#{rand(1_000_000)}"
      f.write("#{const_name} = 1\n")
      f.flush
      mod = Module.new
      mod.autoload(const_name.to_sym, f.path)
      mod.const_get(const_name)
    end
  end

  run_case("is_constant_path", case_seconds) do
    Object.const_get("String")
  end

  # Time
  run_case("rb_strftime_with_timespec", case_seconds) do
    Time.now.strftime("%Y-%m-%d %H:%M:%S %Z")
  end

  run_case("time_inspect", case_seconds) do
    Time.now.inspect
  end

  run_case("time_deconstruct_keys", case_seconds) do
    Time.now.deconstruct_keys([:year, :month, :day])
  end

  run_case("time_mload", case_seconds) do
    Marshal.load(Marshal.dump(Time.now))
  end

  # ISeq / IBF
  run_case("rb_iseq_disasm_recursive", case_seconds) do
    if defined?(RubyVM::InstructionSequence)
      RubyVM::InstructionSequence.compile("a = 1").disasm
    else
      raise "InstructionSequence not available"
    end
  end

  run_case("pm_compile_hash_elements", case_seconds) do
    if defined?(RubyVM::InstructionSequence)
      RubyVM::InstructionSequence.compile("{a: 1, b: 2, c: 3, **{d: 4}}")
    else
      raise "InstructionSequence not available"
    end
  end

  run_case("rb_iseq_ibf_dump", case_seconds) do |i|
    if defined?(RubyVM::InstructionSequence)
      iseq = RubyVM::InstructionSequence.compile("a = 1 + 2")
      bin = iseq.to_binary(POCToStrLarge.new(64 + (i % 64), "x"))
      RubyVM::InstructionSequence.load_from_binary(bin)
    else
      raise "InstructionSequence not available"
    end
  end

  run_case("load_iseq_eval", case_seconds) do
    if defined?(RubyVM::InstructionSequence)
      RubyVM::InstructionSequence.compile("1 + 2").eval
    else
      raise "InstructionSequence not available"
    end
  end

  run_case("ibf_dump_object_string", case_seconds) do
    if defined?(RubyVM::InstructionSequence)
      RubyVM::InstructionSequence.compile("x = 'abc'").to_binary
    else
      raise "InstructionSequence not available"
    end
  end

  run_case("ibf_dump_object_bignum", case_seconds) do
    if defined?(RubyVM::InstructionSequence)
      RubyVM::InstructionSequence.compile("x = 123456789012345678901234567890").to_binary
    else
      raise "InstructionSequence not available"
    end
  end

  run_case("ibf_load_object_string", case_seconds) do
    if defined?(RubyVM::InstructionSequence)
      bin = RubyVM::InstructionSequence.compile("y = 'def'").to_binary
      RubyVM::InstructionSequence.load_from_binary(bin)
    else
      raise "InstructionSequence not available"
    end
  end

  run_case("ibf_load_object_symbol", case_seconds) do
    if defined?(RubyVM::InstructionSequence)
      bin = RubyVM::InstructionSequence.compile("z = :sym").to_binary
      RubyVM::InstructionSequence.load_from_binary(bin)
    else
      raise "InstructionSequence not available"
    end
  end

  # Continuation
  if require_feature("continuation")
    run_case("rb_cont_call", case_seconds) do
      callcc { |cc| cc.call(1) }
    end
  else
    skip_case("rb_cont_call", "missing continuation")
  end

  # Unreachable/privileged or build-time-only hooks
  skip_case("copy_str", "used in ruby.c startup paths")
  skip_case("opt_enc_index", "used in ruby.c startup paths")
  skip_case("rb_report_bug_valist", "internal rb_bug path")
  skip_case("rb_vmdebug_proc_dump_raw", "debug-only API")
  if defined?(RubyVM::YJIT) && RubyVM::YJIT.respond_to?(:enabled?) && RubyVM::YJIT.enabled?
    run_case("rb_yjit_str_simple_append", case_seconds) do
      s = +""
      2000.times { s << "a" }
    end
  else
    skip_case("rb_yjit_str_simple_append", "requires YJIT enabled")
  end

  if defined?(RubyVM::RJIT) && RubyVM::RJIT.respond_to?(:enabled?) && RubyVM::RJIT.enabled?
    run_case("rjit_str_simple_append", case_seconds) do
      s = +""
      2000.times { s << "b" }
    end
  else
    skip_case("rjit_str_simple_append", "requires RJIT enabled")
  end
ensure
  gc_thread.kill if gc_thread
  alloc_thread.kill if alloc_thread
end

puts "all cases complete"
