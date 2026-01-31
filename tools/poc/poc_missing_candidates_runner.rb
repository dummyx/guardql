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
        tolerant_loop(deadline) { "aabbcc".chars.chunk(&:itself).to_a }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "arith_seq_inspect",
    description: "ArithmeticSequence#inspect (enumerator.c:arith_seq_inspect)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) { 1.step(10, 2).inspect }
        puts "OK"
      end
    end
  ),
  CaseDef.new(
    id: "append_method",
    description: "Enumerator#inspect (enumerator.c:append_method)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) { (1..100).each_cons(2).inspect }
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
        tolerant_loop(deadline) { Date.today.strftime("%Y-%m-%d") }
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
        tolerant_loop(deadline) do
          io = StringIO.new
          gz = Zlib::GzipWriter.new(io)
          gz.write("a" * 32)
          gz.finish
          data_io = StringIO.new(io.string)
          Zlib::GzipReader.zcat(data_io)
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
        tolerant_loop(deadline) { Marshal.load(Marshal.dump("a" * 1024)) }
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
          n = (1 << (64 + (i % 256))) + i
          [n].pack("w")
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
    id: "rb_exec_fillarg",
    description: "Process.spawn (process.c:rb_exec_fillarg)",
    run: lambda do |deadline|
      with_pressure do
        require "rbconfig"
        ruby_bin = ENV["POC_RUBY"] || RbConfig.ruby
        env = {}
        32.times { |i| env["POC_K#{i}"] = "V" * 1024 }
        args = Array.new(24) { |i| ("a" * 256) + i.to_s }
        prog = ([ruby_bin, "-e", "exit"] + args).join(" ")
        tolerant_loop(deadline) do
          pid = Process.spawn(env, prog)
          Process.wait(pid)
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
        env = {}
        32.times { |i| env["POC_K#{i}"] = "V" * 1024 }
        args = Array.new(24) { |i| ("b" * 256) + i.to_s }
        prog = ([ruby_bin, "-e", "exit"] + args).join(" ")
        tolerant_loop(deadline) do
          pid = Process.spawn(env, prog)
          Process.wait(pid)
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
        tolerant_loop(deadline) { "a\nb\nc\n".lines.to_a }
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
      pair = transcode_pair
      unless pair
        puts "SKIP: no transcode pair available"
        exit 0
      end
      from_enc, to_enc = pair
      with_pressure do
        tolerant_loop(deadline) do
          ("a" * 256).encode(to_enc, from_enc, invalid: :replace, undef: :replace)
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
        tolerant_loop(deadline) { |i| warn("poc warning #{i}") }
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
        tolerant_loop(deadline) do
          a, b = Socket.pair(:UNIX, :DGRAM, 0)
          begin
            a.sendmsg("hi")
            b.recvmsg
          ensure
            a.close rescue nil
            b.close rescue nil
          end
        end
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
            r.gets
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
    id: "search_required",
    description: "require missing feature (load.c:search_required)",
    run: lambda do |deadline|
      with_pressure do
        tolerant_loop(deadline) do |i|
          begin
            require "missing_feature_#{i}"
          rescue LoadError
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
        tolerant_loop(deadline) { "a\xff".force_encoding("UTF-8").scrub }
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
