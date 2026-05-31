#!/usr/bin/env ruby
# Run with: /path/to/ruby tools/poc/poc_missing_candidates_runner.rb
#
# Runs each missing-guard *candidate* PoC in a forked subprocess so a crash
# doesn't stop the whole run.
#
# Tuning:
# - POC_DURATION=15           per-case seconds
# - POC_CASES=a,b,c           run only selected cases
# - POC_GC_STRESS_MODE=immediate
# - POC_ALLOC_HAMMER=1        enable extra allocation hammer
# - POC_GC_HAMMER_FULL=1      use full_mark+immediate_sweep in GC hammer
# - POC_GC_HAMMER_COMPACT=1   call GC.compact in GC hammer loop
#
# NOTE: This is a *candidate* suite. Many cases may not crash even if the
#       CodeQL result is a true missing-guard; some may be false positives.

require_relative "poc_utils"

STDOUT.sync = true
STDERR.sync = true
Thread.report_on_exception = true

DEFAULT_DURATION = (ENV["POC_DURATION"] || "15").to_f
TIMEOUT_SLACK = 10.0

CaseDef = Struct.new(:id, :description, :run, keyword_init: true)

def now
  Process.clock_gettime(Process::CLOCK_MONOTONIC)
end

def drain_pipe(io, limit_bytes: 64_000)
  data = +""
  while data.bytesize < limit_bytes
    chunk = io.readpartial([4096, limit_bytes - data.bytesize].min)
    data << chunk
  end
  data
rescue EOFError
  data
rescue StandardError
  data
end

def case_enabled?(name)
  only = ENV["POC_CASES"]
  return true if only.nil? || only.empty?
  only.split(",").map(&:strip).include?(name)
end

def require_feature(feature)
  if ENV["POC_ADD_BUILD_LOAD_PATH"] == "1"
    POC.add_build_load_path
    POC.load_optional_transcoders
  end
  require feature
  true
rescue LoadError
  false
end

def with_pressure
  POC.setup_gc
  gc_thread = POC.start_gc_hammer
  alloc_thread = POC.start_alloc_hammer
  yield
ensure
  gc_thread&.kill
  alloc_thread&.kill
end

def tolerant_loop(deadline)
  iterations = 0
  errors = 0
  while now < deadline
    begin
      yield(iterations)
    rescue Exception => e
      raise if e.is_a?(SystemExit) || e.is_a?(SignalException) || e.is_a?(NoMemoryError)
      # Some PoCs use explicit invariant checks that raise (e.g. "CORRUPTION: ...").
      # Those must be treated as failures, not tolerated.
      msg = e.message.to_s
      raise if msg.start_with?("CORRUPTION:") || msg.include?("terminated object")
      errors += 1
      warn("#{e.class}: #{e.message}") if errors <= 3
    end
    iterations += 1
  end
  [iterations, errors]
end

def transcode_pair
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

cases = [
  CaseDef.new(
    id: "chunk_i",
    description: "Enumerable#chunk (enum.c:chunk_i)",
    run: lambda do |deadline|
      with_pressure do
        counter = 0
        tolerant_loop(deadline) do
          (0..200).chunk do |x|
            counter += 1
            if (counter % 10).zero?
              10.times { "x" * 10_000 }
              GC.start(full_mark: true, immediate_sweep: true)
              GC.compact if ENV.fetch("POC_ENABLE_EXPLICIT_COMPACT", "0") == "1" && GC.respond_to?(:compact)
            end
            x & 1
          end.to_a
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "slicebefore_i",
    description: "Enumerable#slice_before (enum.c:slicebefore_i)",
    run: lambda do |deadline|
      with_pressure do
        enum_class = Class.new do
          include Enumerable

          def initialize(values)
            @values = values
          end

          def each
            @values.each do |value|
              yield value
              POC.force_compaction
            end
            POC.force_compaction
          end
        end

        tolerant_loop(deadline) do
          source = enum_class.new((0...24).to_a)
          out = source.slice_before do |x|
            POC.force_compaction if (x % 3).zero?
            (x % 6).zero?
          end.to_a
          expected = [[0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11],
                      [12, 13, 14, 15, 16, 17], [18, 19, 20, 21, 22, 23]]
          raise "CORRUPTION: slice_before mismatch" unless out == expected
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "sliceafter_i",
    description: "Enumerable#slice_after (enum.c:sliceafter_i)",
    run: lambda do |deadline|
      with_pressure do
        enum_class = Class.new do
          include Enumerable

          def initialize(values)
            @values = values
          end

          def each
            @values.each do |value|
              yield value
              POC.force_compaction
            end
            POC.force_compaction
          end
        end

        tolerant_loop(deadline) do
          source = enum_class.new((0...24).to_a)
          out = source.slice_after do |x|
            POC.force_compaction if (x % 3).zero?
            (x % 6) == 5
          end.to_a
          expected = [[0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11],
                      [12, 13, 14, 15, 16, 17], [18, 19, 20, 21, 22, 23]]
          raise "CORRUPTION: slice_after mismatch" unless out == expected
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "slicewhen_i",
    description: "Enumerable#slice_when (enum.c:slicewhen_i)",
    run: lambda do |deadline|
      with_pressure do
        enum_class = Class.new do
          include Enumerable

          def initialize(values)
            @values = values
          end

          def each
            @values.each do |value|
              yield value
              POC.force_compaction
            end
            POC.force_compaction
          end
        end

        tolerant_loop(deadline) do
          source = enum_class.new((0...24).to_a)
          out = source.slice_when do |left, right|
            POC.force_compaction if (right % 3).zero?
            (left % 6) == 5 && right == left + 1
          end.to_a
          expected = [[0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11],
                      [12, 13, 14, 15, 16, 17], [18, 19, 20, 21, 22, 23]]
          raise "CORRUPTION: slice_when mismatch" unless out == expected
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "arith_seq_inspect",
    description: "ArithmeticSequence#inspect (enumerator.c:arith_seq_inspect)",
    run: lambda do |deadline|
      with_pressure do
        klass = Class.new do
          def initialize(tag)
            @tag = tag
          end

          def inspect
            20.times { "x" * 10_000 }
            POC.force_compaction
            "EVIL#{@tag}"
          end

          def coerce(value)
            [value, 1]
          end
        end

        tolerant_loop(deadline) do |i|
          limit = klass.new("limit#{i}")
          step = klass.new("step#{i}")
          inspected = 1.step(limit, step).inspect
          unless inspected.include?("EVILlimit#{i}") && inspected.include?("EVILstep#{i}")
            raise "CORRUPTION: arith_seq_inspect output mismatch: #{inspected.inspect}"
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "append_method",
    description: "Enumerator#inspect (enumerator.c:append_method)",
    run: lambda do |deadline|
      with_pressure do
        klass = Class.new do
          def initialize(tag)
            @tag = tag
          end

          def inspect
            # Try to trigger compaction while append_method still holds
            # a raw pointer into the enumerator argument array.
            20.times { "x" * 10_000 }
            POC.force_compaction
            "EVIL#{@tag}"
          end
        end

        tolerant_loop(deadline) do |i|
          a1 = klass.new("a#{i}")
          a2 = klass.new("b#{i}")
          inspected = (1..100).to_enum(:each_cons, a1, a2).inspect
          unless inspected.include?("EVILa#{i}") && inspected.include?("EVILb#{i}")
            raise "CORRUPTION: append_method output mismatch: #{inspected.inspect}"
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "date_strftime_internal",
    description: "Date#strftime (date_core.c:date_strftime_internal)",
    run: lambda do |deadline|
      unless require_feature("date")
        puts "SKIP: missing date"
        exit 0
      end
      with_pressure do
        fmt = "%Y-%m-%d\0%H:%M:%S"
        tolerant_loop(deadline) { Date.today.strftime(fmt) }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "date_s__strptime_internal",
    description: "Date._strptime (date_core.c:date_s__strptime_internal)",
    run: lambda do |deadline|
      unless require_feature("date")
        puts "SKIP: missing date"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) { Date._strptime("2024-07-05 12:34:56", "%Y-%m-%d %H:%M:%S") }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "minus_dd",
    description: "DateTime#- DateTime (date_core.c:minus_dd)",
    run: lambda do |deadline|
      unless require_feature("date")
        puts "SKIP: missing date"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do |i|
          a = DateTime.jd(Rational(2_459_000 + (i % 17), 1), 12, 34, Rational(56_789_123, 1_000_000), "+00:00")
          b = DateTime.jd(Rational(2_458_900 + (i % 11), 1), 1, 2, Rational(3_456_789, 1_000_000), "+00:00")
          delta = a - b
          POC.force_compaction
          raise "CORRUPTION: invalid DateTime difference" unless delta.is_a?(Rational) && delta > 0
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "cmp_dd",
    description: "DateTime#<=> DateTime (date_core.c:cmp_dd)",
    run: lambda do |deadline|
      unless require_feature("date")
        puts "SKIP: missing date"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do |i|
          a = DateTime.jd(Rational(2_459_000 + (i % 17), 1), 12, 34, Rational(56_789_123, 1_000_000), "+00:00")
          b = DateTime.jd(Rational(2_459_000 + (i % 17), 1), 12, 34, Rational(56_789_124, 1_000_000), "+00:00")
          POC.force_compaction
          raise "CORRUPTION: DateTime compare mismatch" unless (a <=> b) == -1 && (b <=> a) == 1
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "function_call",
    description: "Fiddle::Function#call (function.c:function_call)",
    run: lambda do |deadline|
      unless require_feature("fiddle")
        puts "SKIP: missing fiddle"
        exit 0
      end
      with_pressure do
        handle = Fiddle::Handle.const_defined?(:DEFAULT) ? Fiddle::Handle::DEFAULT : Fiddle::Handle.new(nil)
        strlen_addr =
          begin
            handle["strlen"]
          rescue Fiddle::DLError
            nil
          end
        unless strlen_addr
          puts "SKIP: strlen not available"
          exit 0
        end

        strlen = Fiddle::Function.new(strlen_addr, [Fiddle::Types::VOIDP], Fiddle::Types::SIZE_T)
        tolerant_loop(deadline) do |i|
          text = "guardql-#{i}\0"
          pointer = Fiddle::Pointer[text]
          POC.force_compaction
          out = strlen.call(pointer)
          raise "CORRUPTION: strlen mismatch" unless out == text.bytesize - 1
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "ossl_ec_point_mul",
    description: "OpenSSL::PKey::EC::Point#mul (ossl_pkey_ec.c:ossl_ec_point_mul)",
    run: lambda do |deadline|
      unless require_feature("openssl")
        puts "SKIP: missing openssl"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
          group = OpenSSL::PKey::EC::Group.new("prime256v1")
          group.generator.mul(2)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "ossl_ec_point_add",
    description: "OpenSSL::PKey::EC::Point#add (ossl_pkey_ec.c:ossl_ec_point_add)",
    run: lambda do |deadline|
      unless require_feature("openssl")
        puts "SKIP: missing openssl"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
          group = OpenSSL::PKey::EC::Group.new("prime256v1")
          point = group.generator
          point.add(point)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "ossl_x509name_add_entry",
    description: "OpenSSL::X509::Name#add_entry (ossl_x509name.c:ossl_x509name_add_entry)",
    run: lambda do |deadline|
      unless require_feature("openssl")
        puts "SKIP: missing openssl"
        exit 0
      end
      with_pressure do
        value_class = Class.new do
          def initialize(value)
            @value = value
          end

          def to_str
            POC.force_compaction
            @value.dup
          end
        end

        tolerant_loop(deadline) do |i|
          name = OpenSSL::X509::Name.new
          expected = "guardql-#{i}"
          name.add_entry("CN", value_class.new(expected), OpenSSL::ASN1::UTF8STRING)
          cn = name.to_a.find { |entry| entry[0] == "CN" }
          raise "CORRUPTION: X509 name entry mismatch" unless cn && cn[1] == expected
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "ossl_evp_md_fetch_i",
    description: "OpenSSL::Timestamp allowed_digests fetch (ossl_ts.c:ossl_evp_md_fetch_i)",
    run: lambda do |deadline|
      unless require_feature("openssl")
        puts "SKIP: missing openssl"
        exit 0
      end
      unless OpenSSL.const_defined?(:Timestamp)
        puts "SKIP: OpenSSL::Timestamp not available"
        exit 0
      end

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

      with_pressure do
        tolerant_loop(deadline) do
          fac = OpenSSL::Timestamp::Factory.new
          fac.serial_number = 1
          fac.gen_time = Time.now
          fac.allowed_digests = ["SHA256", "SHA1"]
          fac.default_policy_id = "1.2.3.4.5"
          fac.create_timestamp(key, cert, req)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "start_document_try",
    description: "Psych.dump (psych_emitter.c:start_document_try)",
    run: lambda do |deadline|
      unless require_feature("psych")
        puts "SKIP: missing psych"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) { Psych.dump({ "a" => 1 }) }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rsock_getifaddrs",
    description: "Socket.getifaddrs (ifaddr.c:rsock_getifaddrs)",
    run: lambda do |deadline|
      unless require_feature("socket")
        puts "SKIP: missing socket"
        exit 0
      end
      unless Socket.respond_to?(:getifaddrs)
        puts "SKIP: Socket.getifaddrs not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
          begin
            Socket.getifaddrs
          rescue Errno::EPERM, Errno::EACCES
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "addrinfo_inspect",
    description: "Addrinfo#inspect (raddrinfo.c:addrinfo_inspect)",
    run: lambda do |deadline|
      unless require_feature("socket")
        puts "SKIP: missing socket"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
          Addrinfo.getaddrinfo("localhost", 80, nil, nil, nil, Socket::AI_CANONNAME).each(&:inspect)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rsock_init_unixsock",
    description: "UNIXSocket init (unixsocket.c:rsock_init_unixsock)",
    run: lambda do |deadline|
      unless require_feature("socket")
        puts "SKIP: missing socket"
        exit 0
      end
      unless require_feature("tmpdir")
        puts "SKIP: missing tmpdir"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
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
            ensure
              server.close rescue nil
            end
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_gzreader_s_zcat",
    description: "Zlib::GzipReader.zcat (zlib.c:rb_gzreader_s_zcat)",
    run: lambda do |deadline|
      unless require_feature("zlib")
        puts "SKIP: missing zlib"
        exit 0
      end
      unless require_feature("stringio")
        puts "SKIP: missing stringio"
        exit 0
      end
      with_pressure do
        # Prefer many *tiny* streams so `tmpbuf` is likely embedded, while
        # `buf` still grows and reallocates frequently across streams.
        stream_count = (ENV["POC_ZCAT_STREAMS"] || "32").to_i
        stream_count = 8 if stream_count < 8
        payloads = Array.new(stream_count) { |i| (("a".ord + (i % 3)).chr) }
        expected = payloads.join
        io = StringIO.new(+"")
        payloads.each do |payload|
          gz = Zlib::GzipWriter.new(io)
          gz.write(payload)
          gz.finish
        end
        gz_blob = io.string

        tolerant_loop(deadline) do
          data_io = StringIO.new(gz_blob)
          out = Zlib::GzipReader.zcat(data_io)
          unless out == expected
            raise("CORRUPTION: zcat output mismatch (got=#{out.bytesize} expected=#{expected.bytesize})")
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_check_realpath_emulate",
    description: "File.realdirpath (file.c:rb_check_realpath_emulate)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) { File.realdirpath(".././.", Dir.pwd) }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "path_sub_ext",
    description: "Pathname#sub_ext (pathname.c:path_sub_ext)",
    run: lambda do |deadline|
      unless require_feature("pathname")
        puts "SKIP: missing pathname"
        exit 0
      end
      with_pressure do
        repl_class = Class.new do
          def initialize(value)
            @value = value
          end

          def to_str
            POC.force_compaction
            @value.dup
          end
        end

        tolerant_loop(deadline) do |i|
          pathname = Pathname.new("dir/base#{i}.txt")
          out = pathname.sub_ext(repl_class.new(".rb"))
          raise "CORRUPTION: sub_ext mismatch" unless out.to_s == "dir/base#{i}.rb"
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "argf_next_argv",
    description: "ARGF.each_line (io.c:argf_next_argv)",
    run: lambda do |deadline|
      unless require_feature("tmpdir")
        puts "SKIP: missing tmpdir"
        exit 0
      end
      with_pressure do
        orig_argv = ARGV.dup
        begin
          tolerant_loop(deadline) do |i|
            Dir.mktmpdir do |dir|
              f1 = File.join(dir, "a.txt")
              f2 = File.join(dir, "b.txt")
              File.write(f1, "a#{i}\n")
              File.write(f2, "b#{i}\n")
              ARGV.replace([f1, f2])
              ARGF.each_line { |line| line }
            end
          end
        ensure
          ARGV.replace(orig_argv)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "load_iseq_eval",
    description: "RubyVM::InstructionSequence#eval (load.c:load_iseq_eval)",
    run: lambda do |deadline|
      unless defined?(RubyVM::InstructionSequence)
        puts "SKIP: InstructionSequence not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) { RubyVM::InstructionSequence.compile("1 + 2").eval }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "r_bytes1_buffered",
    description: "Marshal.load (marshal.c:r_bytes1_buffered)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do
          s = "a" * 1024
          out = Marshal.load(Marshal.dump(s))
          raise "CORRUPTION: marshal string mismatch" unless out == s && out.bytesize == s.bytesize
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "pack_pack",
    description: "Array#pack (pack.c:pack_pack)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do |i|
          # Exercise 'w' (BER compressed integer) which allocates a temporary
          # string buffer and then appends it into the result.
          #
          # If the temporary buffer is freed/collected while raw pointers into it
          # are used, the packed bytes can become corrupted. Detect via roundtrip.
          n = (1 << (200 + (i % 80))) + i
          packed = [n].pack("w")
          unpacked = packed.unpack1("w")
          raise "CORRUPTION: pack/unpack mismatch at iteration=#{i}" unless unpacked == n
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "proc_binding",
    description: "Proc#binding (proc.c:proc_binding)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do
          x = rand(1000)
          proc { x }.binding.local_variable_get(:x)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "curry",
    description: "Proc#curry (proc.c:curry)",
    run: lambda do |deadline|
      with_pressure do
        p = lambda do |a, b, &blk|
          50.times { "x" * 10_000 }
          GC.start(full_mark: true, immediate_sweep: true)
          GC.compact if ENV.fetch("POC_ENABLE_EXPLICIT_COMPACT", "0") == "1" && GC.respond_to?(:compact)
          blk&.call
          a.to_s
          b.to_s
          nil
        end
        curried = p.curry(2)
        tolerant_loop(deadline) do |i|
          curried.call(i).call(i + 1) { "y" * 1024 }
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_exec_fillarg",
    description: "Process.spawn (process.c:rb_exec_fillarg)",
    run: lambda do |deadline|
      with_pressure do
        require "rbconfig"
        ruby_bin = ENV["POC_RUBY"] || RbConfig.ruby
        env = {}

        # Hit the argv[] conversion path:
        #   for each arg: s = StringValueCStr(arg); rb_str_buf_cat(argv_buf, s, ...)
        #
        # Use many *small* (likely embedded) strings so compaction can move them,
        # making stale C pointers more likely if missing guards are real.
        arg_count = (ENV["POC_SPAWN_ARGC"] || "300").to_i
        arg_count = 50 if arg_count < 50

        tolerant_loop(deadline) do |iter|
          args = Array.new(arg_count) { |i| "a#{iter}_#{i}" }
          pid = Process.spawn(env, ruby_bin, "-e", "exit", "--", *args)
          Process.wait(pid)
        rescue Errno::E2BIG, ArgumentError
          # If the platform rejects very large argv/env, keep going.
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_execarg_parent_start1",
    description: "Process.spawn parent start (process.c:rb_execarg_parent_start1)",
    run: lambda do |deadline|
      with_pressure do
        require "rbconfig"
        ruby_bin = ENV["POC_RUBY"] || RbConfig.ruby
        # Keep env keys/values small (more likely embedded) and numerous
        # enough to trigger growth in env buffers.
        env_count = (ENV["POC_SPAWN_ENV"] || "200").to_i
        env_count = 10 if env_count < 10

        tolerant_loop(deadline) do |iter|
          env = {}
          env_count.times { |i| env["K#{iter}_#{i}"] = "V#{i}" }
          pid = Process.spawn(env, ruby_bin, "-e", "exit")
          Process.wait(pid)
        rescue Errno::E2BIG, ArgumentError
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "process_sflag",
    description: "Ruby -s flag parsing (ruby.c:process_sflag)",
    run: lambda do |deadline|
      with_pressure do
        require "rbconfig"
        ruby_bin = ENV["POC_RUBY"] || RbConfig.ruby
        env = {}
        32.times { |i| env["POC_K#{i}"] = "V" * 1024 }
        sflags = Array.new(64) { |i| "-foo#{i}=#{'x' * 256}" }
        tolerant_loop(deadline) do
          pid = Process.spawn(env, ruby_bin, "-s", "-e", "exit", "--", *sflags)
          Process.wait(pid)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_reg_preprocess_dregexp",
    description: "Interpolated regexp (re.c:rb_reg_preprocess_dregexp)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do
          s = "ab"
          /#{s}/ =~ "ab"
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_parser_lex_get_str",
    description: "Ripper.lex (ruby_parser.c:rb_parser_lex_get_str)",
    run: lambda do |deadline|
      unless require_feature("ripper")
        puts "SKIP: missing ripper"
        exit 0
      end
      unless defined?(Ripper) && Ripper.respond_to?(:lex)
        puts "SKIP: Ripper.lex not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) { Ripper.lex("a = 1\n") }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_str_enumerate_lines",
    description: "String#lines (string.c:rb_str_enumerate_lines)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do |i|
          sep = "X"
          s = ("a#{i}Xb#{i}Xc#{i}X" * 2)
          out = +""
          n = 0
          s.each_line(sep) do |line|
            if (n % 2).zero?
              10.times { "x" * 4096 }
              GC.start(full_mark: true, immediate_sweep: true)
            end
            out << line
            n += 1
          end

          raise "CORRUPTION: each_line mismatch (custom rs)" unless out == s

          # Also exercise the non-ascii-compatible encoding path where
          # rb_str_enumerate_lines creates an encoded copy of the default record
          # separator and then keeps scanning using raw pointers into it.
          utf16 = ("a\nb\nc\nd\ne\n" * 50).encode("UTF-16LE")
          out2 = +"".force_encoding(utf16.encoding)
          n = 0
          utf16.each_line do |line|
            if (n % 10).zero?
              20.times { "y" * 4096 }
              GC.start(full_mark: true, immediate_sweep: true)
            end
            out2 << line
            n += 1
          end
          raise "CORRUPTION: each_line mismatch (default rs, UTF-16LE)" unless out2 == utf16
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_str_format_m",
    description: "String#% (string.c:rb_str_format_m)",
    run: lambda do |deadline|
      with_pressure do
        klass = Class.new do
          def initialize(tag)
            @tag = tag
          end

          def to_s
            50.times { "x" * 10_000 }
            GC.start(full_mark: true, immediate_sweep: true)
            GC.compact if ENV.fetch("POC_ENABLE_EXPLICIT_COMPACT", "0") == "1" && GC.respond_to?(:compact)
            "EVIL#{@tag}"
          end
        end

        wrap = Class.new do
          def initialize(i, klass)
            @i = i
            @klass = klass
          end

          def to_ary
            [@klass.new(@i), @klass.new(@i + 1)]
          end
        end

        fmt = "%s-%s"
        tolerant_loop(deadline) { |i| fmt % wrap.new(i, klass) }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_str_s_new",
    description: "String.new (string.c:rb_str_s_new)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do |i|
          orig = "a" * (128 + (i % 256))
          enc = (i % 2).zero? ? Encoding::UTF_8 : "UTF-8"
          String.new(orig, encoding: enc, capacity: 1024 + (i % 1024))
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "thread_do_start_proc",
    description: "Thread.new with args (thread.c:thread_do_start_proc)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do |i|
          args = Array.new(10) { "x" * (128 + (i % 128)) }
          t = Thread.new(*args) { |*xs| xs.length }
          t.join
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "str_transcode0",
    description: "String#encode (transcode.c:str_transcode0)",
    run: lambda do |deadline|
      with_pressure do
        # Force the branch where non-ASCII-compatible source and destination
        # encodings plus decorators convert `str` to a temporary UTF-8 string
        # before `RSTRING_PTR(str)` is used across `rb_str_tmp_new`.
        tolerant_loop(deadline) do |i|
          POC.force_compaction if (i % 5).zero?
          POC.exercise_str_transcode0(i)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "ibf_dump_object_string",
    description: "InstructionSequence#to_binary string (compile.c:ibf_dump_object_string)",
    run: lambda do |deadline|
      unless defined?(RubyVM::InstructionSequence)
        puts "SKIP: InstructionSequence not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) { RubyVM::InstructionSequence.compile("x = 'abc'").to_binary }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "ibf_dump_object_bignum",
    description: "InstructionSequence#to_binary bignum (compile.c:ibf_dump_object_bignum)",
    run: lambda do |deadline|
      unless defined?(RubyVM::InstructionSequence)
        puts "SKIP: InstructionSequence not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
          RubyVM::InstructionSequence.compile("x = 123456789012345678901234567890").to_binary
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_warn_m",
    description: "Kernel.warn (error.c:rb_warn_m)",
    run: lambda do |deadline|
      with_pressure do
        $stderr = File.open(File::NULL, "w")

        klass = Class.new do
          def initialize(tag)
            @tag = tag
          end

          def to_s
            20.times { "x" * 10_000 }
            GC.start(full_mark: true, immediate_sweep: true)
            GC.compact if ENV.fetch("POC_ENABLE_EXPLICIT_COMPACT", "0") == "1" && GC.respond_to?(:compact)
            "EVIL#{@tag}"
          end
        end

        tolerant_loop(deadline) do |i|
          warn(klass.new(i), klass.new(i + 1))
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "bsock_sendmsg_internal",
    description: "Socket#sendmsg (ancdata.c:bsock_sendmsg_internal)",
    run: lambda do |deadline|
      unless require_feature("socket")
        puts "SKIP: missing socket"
        exit 0
      end
      unless Socket.instance_methods.include?(:sendmsg)
        puts "SKIP: sendmsg not available"
        exit 0
      end
      with_pressure do
        sender, receiver = Socket.pair(:UNIX, :DGRAM, 0)

          klass = Class.new do
            def to_str
              40.times { "x" * 10_000 }
              GC.start(full_mark: true, immediate_sweep: true)
              Socket.sockaddr_un("\0poc_missing_sendmsg_#{rand(1_000_000)}")
            end
          end

          tolerant_loop(deadline) do
            begin
              sender.sendmsg("hi", 0, klass.new)
            rescue Errno::ECONNREFUSED, Errno::EINVAL, Errno::ENOENT
              # Expected: sending to a non-existent abstract UNIX address.
            rescue Errno::EFAULT
              raise("CORRUPTION: sendmsg got EFAULT")
            end
          end

          sender.close rescue nil
          receiver.close rescue nil
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "make_inspectname",
    description: "Addrinfo inspect helper (raddrinfo.c:make_inspectname)",
    run: lambda do |deadline|
      unless require_feature("socket")
        puts "SKIP: missing socket"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
          Addrinfo.getaddrinfo("localhost", "http", nil, nil, nil, Socket::AI_CANONNAME).each(&:inspect)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_io_getline_1",
    description: "IO#gets (io.c:rb_io_getline_1)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do |i|
          r, w = IO.pipe
          begin
            w.write("line#{i}\n")
            w.close
            line = r.gets
            raise "CORRUPTION: gets mismatch" unless line == "line#{i}\n"
          ensure
            r.close rescue nil
            w.close rescue nil
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_io_buffer_map",
    description: "IO::Buffer.map (io_buffer.c:rb_io_buffer_map)",
    run: lambda do |deadline|
      unless defined?(IO::Buffer) && IO::Buffer.respond_to?(:map)
        puts "SKIP: IO::Buffer.map not available"
        exit 0
      end
      unless require_feature("tmpdir")
        puts "SKIP: missing tmpdir"
        exit 0
      end
      with_pressure do
        proxy_class = Class.new do
          def initialize(io)
            @io = io
          end

          def fileno
            POC.force_compaction
            @io.fileno
          end
        end

        flags = IO::Buffer.const_defined?(:READONLY) ? IO::Buffer::READONLY : 0
        Dir.mktmpdir("guardql-io-buffer-map") do |dir|
          path = File.join(dir, "data.bin")
          tolerant_loop(deadline) do |i|
            payload = "map#{i}-" * 32
            File.binwrite(path, payload)
            File.open(path, "rb") do |file|
              buffer = IO::Buffer.map(proxy_class.new(file), payload.bytesize, 0, flags)
              begin
                out = buffer.get_string(0, payload.bytesize)
                raise "CORRUPTION: IO::Buffer.map mismatch" unless out == payload
              ensure
                buffer.free if buffer.respond_to?(:free)
              end
            end
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_iseq_disasm_recursive",
    description: "InstructionSequence#disasm (iseq.c:rb_iseq_disasm_recursive)",
    run: lambda do |deadline|
      unless defined?(RubyVM::InstructionSequence)
        puts "SKIP: InstructionSequence not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) { RubyVM::InstructionSequence.compile("a = 1").disasm }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "enum_minmax_by",
    description: "Enumerable#minmax_by (enum.c:enum_minmax_by)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do |i|
          ary = [i, i + 1, i + 2, i + 3, -i]
          min, max = ary.minmax_by { |x| x * x - x }
          raise "unexpected nil min/max" if min.nil? || max.nil?
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_struct_alloc",
    description: "Struct allocation (struct.c:rb_struct_alloc)",
    run: lambda do |deadline|
      with_pressure do
        klass = Struct.new(:a, :b, :c)
        tolerant_loop(deadline) do |i|
          obj = klass.new(i, i + 1, i + 2)
          raise "bad struct value" unless obj.a == i && obj.c == i + 2
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "str_new_frozen_buffer",
    description: "String.new from frozen source (string.c:str_new_frozen_buffer)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do |i|
          src = ("S#{i}" * 64).freeze
          s = String.new(src)
          raise "size mismatch" unless s.bytesize == src.bytesize
          raise "content mismatch" unless s == src
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_strftime_with_timespec",
    description: "Time#strftime (strftime.c:rb_strftime_with_timespec)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do
          t = Time.now
          out = t.strftime("%Y-%m-%d %H:%M:%S.%9N %z %Z")
          raise "empty strftime output" if out.nil? || out.empty?
          raise "missing year" unless out.match?(/\d{4}/)
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "r_object_for",
    description: "Marshal.load object path (marshal.c:r_object_for)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do |i|
          obj = {
            "id" => i,
            "ary" => [i, i + 1, "x" * 64],
            "h" => { "k#{i}" => "v#{i}" }
          }
          loaded = Marshal.load(Marshal.dump(obj))
          raise "marshal mismatch" unless loaded == obj
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "w_object",
    description: "Marshal.dump user object path (marshal.c:w_object)",
    run: lambda do |deadline|
      with_pressure do
        klass = Class.new do
          attr_reader :payload

          def initialize(payload)
            @payload = payload
          end

          def _dump(_level)
            POC.force_compaction
            @payload.dup
          end

          def self._load(payload)
            new(payload)
          end
        end

        tolerant_loop(deadline) do |i|
          expected = "marshal-#{i}-" * 16
          loaded = Marshal.load(Marshal.dump(klass.new(expected)))
          raise "CORRUPTION: marshal _dump mismatch" unless loaded.payload == expected
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_iseq_ibf_dump",
    description: "InstructionSequence#to_binary (compile.c:rb_iseq_ibf_dump)",
    run: lambda do |deadline|
      unless defined?(RubyVM::InstructionSequence)
        puts "SKIP: InstructionSequence not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do |i|
          src = "x = #{i}; y = x + 1; y"
          iseq = RubyVM::InstructionSequence.compile(src)
          bin = iseq.to_binary
          raise "empty iseq binary" if bin.nil? || bin.empty?
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "builtin_iseq_load",
    description: "InstructionSequence.load_from_binary (mini_builtin.c:builtin_iseq_load)",
    run: lambda do |deadline|
      unless defined?(RubyVM::InstructionSequence) &&
             RubyVM::InstructionSequence.respond_to?(:load_from_binary)
        puts "SKIP: load_from_binary not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
          iseq = RubyVM::InstructionSequence.compile("40 + 2")
          loaded = RubyVM::InstructionSequence.load_from_binary(iseq.to_binary)
          result = loaded.eval
          raise "unexpected eval result: #{result.inspect}" unless result == 42
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "eval_make_iseq",
    description: "Kernel.eval iseq path (vm_eval.c:eval_make_iseq)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do
          result = eval("6 * 7")
          raise "eval mismatch" unless result == 42
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "new_child_iseq",
    description: "Nested compile path (compile.c:new_child_iseq)",
    run: lambda do |deadline|
      unless defined?(RubyVM::InstructionSequence)
        puts "SKIP: InstructionSequence not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do |i|
          src = <<~RUBY
            def outer_#{i}
              ->(x) { x + 1 }.call(41)
            end
            outer_#{i}
          RUBY
          iseq = RubyVM::InstructionSequence.compile(src)
          result = iseq.eval
          raise "unexpected result: #{result.inspect}" unless result == 42
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "compile_builtin_mandatory_only_method",
    description: "Builtin mandatory-only compile (compile.c:compile_builtin_mandatory_only_method)",
    run: lambda do |deadline|
      unless defined?(RubyVM::InstructionSequence)
        puts "SKIP: InstructionSequence not available"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
          src = <<~RUBY
            ary = [1, 2, 3]
            ary.map { _1 + 1 }
          RUBY
          iseq = RubyVM::InstructionSequence.compile(src)
          out = iseq.eval
          raise "bad map result" unless out == [2, 3, 4]
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "search_required",
    description: "require missing feature (load.c:search_required)",
    run: lambda do |deadline|
      unless require_feature("tmpdir")
        puts "SKIP: missing tmpdir"
        exit 0
      end
      with_pressure do
        Dir.mktmpdir("poc-search-required") do |dir|
          $LOAD_PATH.unshift(dir)

          tolerant_loop(deadline) do |i|
            feature = "guardql_req_#{i}_#{rand(1_000_000)}"
            File.write(File.join(dir, "#{feature}.rb"), "# guardql #{i}\n")
            require feature
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "qpencode",
    description: "pack('M') (pack.c:qpencode)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) { ["a" * 200].pack("M") }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "extract_options",
    description: "Prism.parse with filepath (prism/extension.c:extract_options)",
    run: lambda do |deadline|
      unless require_feature("prism")
        puts "SKIP: missing prism"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) { Prism.parse("a = 1", filepath: "poc.rb", line: 1) }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_proc_compose_to_left",
    description: "Proc#<< composition (proc.c:rb_proc_compose_to_left)",
    run: lambda do |deadline|
      with_pressure do
        f = ->(x) { x + 1 }
        g = ->(x) { x * 2 }
        tolerant_loop(deadline) { (f << g).call(3) }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_reg_prepare_re",
    description: "Regexp prepare (re.c:rb_reg_prepare_re)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) { /a.+b/ =~ "axxb" }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "enc_str_scrub",
    description: "String#scrub (string.c:enc_str_scrub)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do
          "a\xff".force_encoding("UTF-8").scrub do |_bytes|
            20.times { "x" * 10_000 }
            GC.start(full_mark: true, immediate_sweep: true)
            GC.compact if ENV.fetch("POC_ENABLE_EXPLICIT_COMPACT", "0") == "1" && GC.respond_to?(:compact)
            "b"
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "str_replace_shared_without_enc",
    description: "String#replace (string.c:str_replace_shared_without_enc)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do
          s = "abc"
          t = s.dup
          t.replace("def")
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_tracepoint_enable_for_target",
    description: "TracePoint#enable(target:) (vm_trace.c:rb_tracepoint_enable_for_target)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do
          tp = TracePoint.new(:call) {}
          begin
            tp.enable(target: Thread.current) { "trace".to_s }
          rescue ArgumentError
          ensure
            tp.disable rescue nil
          end
        end
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "rb_yjit_str_simple_append",
    description: "YJIT string append helper (yjit.c:rb_yjit_str_simple_append)",
    run: lambda do |deadline|
      unless defined?(RubyVM::YJIT)
        puts "SKIP: YJIT not available"
        exit 0
      end
      RubyVM::YJIT.enable if RubyVM::YJIT.respond_to?(:enable)
      unless RubyVM::YJIT.respond_to?(:enabled?) && RubyVM::YJIT.enabled?
        puts "SKIP: YJIT not enabled"
        exit 0
      end
      with_pressure do
        tolerant_loop(deadline) do
          s = +""
          2000.times { s << "a" }
        end
        puts "OK"
      end
    end
  )

]

def recursive_gap_tick(iteration)
  8.times { ("guardlint-#{iteration}-" * 128).dup.freeze }
  return unless (iteration % 16).zero?

  GC.start(full_mark: true, immediate_sweep: true)
  GC.compact if ENV.fetch("POC_ENABLE_EXPLICIT_COMPACT", "0") == "1" && GC.respond_to?(:compact)
end

def recursive_gap_big_number(iteration)
  bits = 4096 + (iteration % 11) * 257
  a = (1 << bits) + (iteration * 17) + 3
  b = (1 << (bits - 97)) + (iteration * 31) + 5
  ((a * b) ^ (a & b) ^ (a | b)).to_s(36).bytesize
  (a * a).to_s(16).bytesize
  Integer("f" * (128 + iteration % 64), 16)
end

def recursive_gap_rm_rf(path)
  if File.directory?(path) && !File.symlink?(path)
    Dir.children(path).each { |child| recursive_gap_rm_rf(File.join(path, child)) }
    Dir.rmdir(path) rescue nil
  else
    File.delete(path) rescue nil
  end
end

def recursive_gap_tempdir(prefix)
  base = ENV["TMPDIR"] || "/tmp"
  dir = File.join(base, "#{prefix}-#{$$}-#{(now * 1000).to_i}")
  Dir.mkdir(dir)
  yield dir
ensure
  recursive_gap_rm_rf(dir) if dir
end

def recursive_gap_autoload_workload(deadline)
  tolerant_loop(deadline) do |i|
    recursive_gap_tick(i)
    cname = :"GuardLintAutoloadConst#{i % 256}"
    path = "/tmp/guardlint_missing_autoload_#{$$}_#{i % 256}.rb"
    Object.__send__(:remove_const, cname) rescue nil
    Object.autoload(cname, path)
    Object.const_defined?(cname, false)
    Object.const_get(cname, false) rescue nil
    Object.__send__(:remove_const, cname) rescue nil
  end
end

def recursive_gap_io_workload(kind, deadline)
  require "io/nonblock" if kind.to_s.start_with?("io_") || kind == "select" rescue nil
  tolerant_loop(deadline) do |i|
    recursive_gap_tick(i)
    case kind
    when "io_read_nonblock"
      r, w = IO.pipe
      begin
        r.nonblock = true
        w.write("x" * 128)
        r.read_nonblock(32, exception: false)
      ensure
        r.close rescue nil
        w.close rescue nil
      end
    when "io_write_nonblock"
      r, w = IO.pipe
      begin
        w.nonblock = true
        w.write_nonblock("x" * 128, exception: false)
      ensure
        r.close rescue nil
        w.close rescue nil
      end
    when "io_reopen"
      f = File.open(File::NULL, "r")
      begin
        f.reopen(File::NULL, "r")
      ensure
        f.close rescue nil
      end
    when "io_close_exec"
      r, w = IO.pipe
      begin
        r.close_on_exec = i.even?
        w.close_on_exec = i.odd?
        r.close_on_exec?
        w.close_on_exec?
      ensure
        r.close rescue nil
        w.close rescue nil
      end
    when "select"
      r, w = IO.pipe
      begin
        IO.select([r], [w], nil, 0)
      ensure
        r.close rescue nil
        w.close rescue nil
      end
    when "getline"
      r, w = IO.pipe
      begin
        w.write("line-#{i}\n")
        w.close
        r.gets
      ensure
        r.close rescue nil
        w.close rescue nil
      end
    end
  end
end

def recursive_gap_workload(kind, deadline)
  with_pressure do
    case kind
    when "array_share"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        base = (0...128).to_a
        shared = base[16, 96]
        shared.unshift(i, i + 1, i + 2)
        shared.shift(3)
        base.clear
      end
    when "autoload"
      recursive_gap_autoload_workload(deadline)
    when "bignum"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        recursive_gap_big_number(i)
      end
    when "env"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        key = "GUARDLINT_POC_ENV_#{i % 32}"
        ENV[key] = "value-#{i}"
        ENV.delete(key) if (i % 3).zero?
        ENV.clear if ENV["GUARDLINT_ALLOW_ENV_CLEAR"] == "1" && (i % 128).zero?
      end
    when "feature_index", "load_file"
      recursive_gap_tempdir("guardlint-load") do |dir|
        entries = Array.new(16) do |j|
          stem = "guardlint_feature_#{j}"
          path = File.join(dir, "#{stem}.rb")
          File.write(path, "GuardLintFeatureValue#{j} = #{j}\n")
          [stem, path]
        end
        $LOAD_PATH.unshift(dir)
        begin
          tolerant_loop(deadline) do |i|
            recursive_gap_tick(i)
            stem, path = entries[i % entries.length]
            require stem rescue nil
            load path rescue nil
          end
        ensure
          $LOAD_PATH.delete(dir)
        end
      end
    when "fstring"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        a = -"guardlint-fstring-#{i % 256}"
        b = -"guardlint-fstring-#{(i + 1) % 256}"
        a == b
        { a => i }.fetch(a)
      end
    when "io_read_nonblock", "io_write_nonblock", "io_reopen", "io_close_exec", "select", "getline"
      recursive_gap_io_workload(kind, deadline)
    when "iseq"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        iseq = RubyVM::InstructionSequence.compile("x = #{i}; x + 1")
        RubyVM::InstructionSequence.load_from_binary(iseq.to_binary).eval rescue iseq.eval
      end
    when "name_error"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        begin
          Object.new.__send__(:"guardlint_missing_#{i}")
        rescue NameError => e
          e.message
          e.to_s
        end
      end
    when "enumerator_next"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        enum = [i, i + 1, i + 2].each
        enum.next
        enum.next
      end
    when "ractor"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        next unless defined?(Ractor)
        r = Ractor.new(i) { |v| v + 1 }
        r.take rescue nil
      end
    when "box"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        if defined?(RubyVM::Box) && RubyVM::Box.respond_to?(:new)
          box = RubyVM::Box.new rescue nil
          box.object_id if box
        else
          mod = Module.new
          mod.const_set(:"GuardLintBox#{i % 32}", i)
          mod.constants(false)
        end
      end
    when "set"
      set_loaded = begin
        require "set"
        true
      rescue LoadError
        false
      end
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        if set_loaded
          a = Set.new((0...64).map { |x| "a#{x + i}" })
          b = Set.new((32...96).map { |x| "a#{x + i}" })
          (a & b).to_a
          a.add("a#{i}")
        else
          a = (0...64).map { |x| "a#{x + i}" }
          b = (32...96).map { |x| "a#{x + i}" }
          a & b
        end
      end
    when "encoding_converter"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        conv = Encoding::Converter.new("UTF-8", (i.even? ? "UTF-16LE" : "EUC-JP"))
        conv.convert("guardlint-#{i}")
        conv.finish rescue nil
      end
    when "gc_mark"
      tolerant_loop(deadline) do |i|
        objects = Array.new(64) { |j| ["guardlint", i, j, { j => "x" * 32 }] }
        recursive_gap_tick(i)
        GC.start(full_mark: true, immediate_sweep: true)
        objects.hash
      end
    when "proc_hash"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        proc { i }.hash
      end
    when "object_copy"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        obj = Object.new
        obj.instance_variable_set(:@guardlint, "x" * 128)
        obj.dup.instance_variables
      end
    when "singleton_method"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        obj = Object.new
        obj.define_singleton_method(:guardlint_poc) { i }
        obj.singleton_method(:guardlint_poc)
        obj.method(:guardlint_poc).call
      end
    when "string_chars"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        "a\u0301b#{i}".each_char.to_a
      end
    when "string_codepoints"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        "a\u0301b#{i}".each_codepoint.to_a
      end
    when "string_graphemes"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        s = "a\u0301b#{i}"
        s.each_grapheme_cluster.to_a if s.respond_to?(:each_grapheme_cluster)
      end
    when "string_casecmp"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        "GuardLint#{i}".casecmp("guardlint#{i}")
        "GuardLint#{i}".casecmp?("guardlint#{i}")
      end
    when "time_at"
      tolerant_loop(deadline) do |i|
        recursive_gap_tick(i)
        Time.at(Rational(i % 1000, 3))
        Time.at(i % 1_000_000, i % 1_000_000, :usec)
      end
    else
      raise "unknown recursive gap workload: #{kind}"
    end
    puts "OK"
  end
end

RECURSIVE_GAP_CASES = {
  "ary_ensure_room_for_unshift" => ["Array#unshift on shared arrays", "array_share"],
  "rb_ary_cancel_sharing" => ["Array sharing cancellation", "array_share"],
  "autoload_copy_table_for_box_i" => ["autoload table copy callback", "autoload"],
  "autoload_data_for_named_constant" => ["autoload lookup for named constants", "autoload"],
  "autoload_delete" => ["autoload deletion paths", "autoload"],
  "autoload_load_needed" => ["autoload load-needed checks", "autoload"],
  "check_autoload_required" => ["autoload/require checks", "autoload"],
  "rb_autoload_copy_table_for_box" => ["autoload table copy for Box", "autoload"],
  "bigmul0" => ["large Integer multiplication", "bignum"],
  "bigsq" => ["large Integer squaring", "bignum"],
  "rb_big_and" => ["large Integer bitwise AND", "bignum"],
  "rb_big_mul_balance" => ["balanced large Integer multiplication", "bignum"],
  "rb_big_mul_karatsuba" => ["Karatsuba large Integer multiplication", "bignum"],
  "rb_big_mul_toom3" => ["Toom-3 large Integer multiplication", "bignum"],
  "rb_big_or" => ["large Integer bitwise OR", "bignum"],
  "rb_big_xor" => ["large Integer bitwise XOR", "bignum"],
  "str2big_karatsuba" => ["large Integer parsing", "bignum"],
  "check_getline_args" => ["IO getline argument handling", "getline"],
  "env_aset" => ["ENV assignment", "env"],
  "rb_env_clear" => ["ENV clear/assignment paths", "env"],
  "features_index_add" => ["feature index updates through require", "feature_index"],
  "fstring_cmp" => ["fstring comparison", "fstring"],
  "fstring_concurrent_set_cmp" => ["concurrent fstring set comparison", "fstring"],
  "io_read_nonblock" => ["IO#read_nonblock", "io_read_nonblock"],
  "io_reopen" => ["IO#reopen", "io_reopen"],
  "io_write_nonblock" => ["IO#write_nonblock", "io_write_nonblock"],
  "rb_io_close_on_exec_p" => ["IO close-on-exec query", "io_close_exec"],
  "rb_io_set_close_on_exec" => ["IO close-on-exec setter", "io_close_exec"],
  "select_internal" => ["IO.select", "select"],
  "iseq_build_from_ary_body" => ["InstructionSequence binary load", "iseq"],
  "rb_iseq_compile_with_option" => ["InstructionSequence compile with options", "iseq"],
  "load_file_internal" => ["load/require file execution", "load_file"],
  "name_err_mesg_to_str" => ["NameError message formatting", "name_error"],
  "next_i" => ["Enumerator#next", "enumerator_next"],
  "ractor_unmonitor" => ["Ractor lifecycle", "ractor"],
  "rb_ractor_channel_close" => ["Ractor channel close/lifecycle", "ractor"],
  "rb_box_local_extension" => ["Box local-extension path when available", "box"],
  "rb_concurrent_set_find_or_insert" => ["Set/concurrent-set insertion path", "set"],
  "set_i_intersection" => ["Set intersection", "set"],
  "rb_econv_init_by_convpath" => ["Encoding converter initialization", "encoding_converter"],
  "rb_gc_mark_children" => ["GC mark children traversal", "gc_mark"],
  "rb_hash_proc" => ["Proc#hash", "proc_hash"],
  "rb_obj_copy_ivar" => ["Object copy ivar path", "object_copy"],
  "rb_obj_singleton_method" => ["Object#singleton_method", "singleton_method"],
  "rb_str_enumerate_chars" => ["String#each_char", "string_chars"],
  "rb_str_enumerate_codepoints" => ["String#each_codepoint", "string_codepoints"],
  "rb_str_enumerate_grapheme_clusters" => ["String#each_grapheme_cluster", "string_graphemes"],
  "str_casecmp" => ["String#casecmp and casecmp?", "string_casecmp"],
  "time_s_at" => ["Time.at", "time_at"]
}.freeze

cases.concat(
  RECURSIVE_GAP_CASES.map do |id, (description, kind)|
    CaseDef.new(
      id: id,
      description: "#{description} (recursive-trigger gap PoC)",
      run: lambda { |deadline| recursive_gap_workload(kind, deadline) }
    )
  end
)

max_id_len = cases.map { |c| c.id.length }.max || 0
any_fail = false

cases.each do |c|
  next unless case_enabled?(c.id)

  duration_s = DEFAULT_DURATION
  timeout_s = duration_s + TIMEOUT_SLACK

  out_r, out_w = IO.pipe
  err_r, err_w = IO.pipe

  pid = fork do
    out_r.close
    err_r.close
    STDOUT.reopen(out_w)
    STDERR.reopen(err_w)
    out_w.close
    err_w.close

    begin
      deadline = now + duration_s
      c.run.call(deadline)
      exit 0
    rescue SystemExit => e
      raise e
    rescue Exception => e
      warn("#{e.class}: #{e.message}")
      warn(e.backtrace.join("\n")) if e.backtrace
      exit 2
    end
  end

  out_w.close
  err_w.close

  status = nil
  timed_out = false
  deadline = now + timeout_s

  while now < deadline
    wpid, wstatus = Process.waitpid2(pid, Process::WNOHANG)
    if wpid
      status = wstatus
      break
    end
    sleep 0.05
  end

  if status.nil?
    timed_out = true
    begin
      Process.kill("TERM", pid)
    rescue Errno::ESRCH
    end
    sleep 0.2
    begin
      Process.kill("KILL", pid)
    rescue Errno::ESRCH
    end
    begin
      _, status = Process.waitpid2(pid)
    rescue Errno::ECHILD
    end
  end

  stderr = drain_pipe(err_r)
  stdout = drain_pipe(out_r)
  err_r.close
  out_r.close

  label =
    if timed_out
      any_fail = true
      "TIME"
    elsif status&.signaled?
      any_fail = true
      "CRASH"
    elsif status&.exitstatus == 0
      stdout.start_with?("SKIP:") ? "SKIP" : "PASS"
    else
      any_fail = true
      "ERROR"
    end

  puts "#{label.ljust(5)} #{c.id.ljust(max_id_len)} - #{c.description}"

  next unless %w[CRASH ERROR TIME].include?(label)

  snippet = (stderr + stdout).lines.first(20).join
  puts snippet.empty? ? "(no output captured)" : snippet
end

exit(any_fail ? 1 : 0)
