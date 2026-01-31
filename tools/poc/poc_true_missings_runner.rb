# Run with: /path/to/ruby tools/poc/poc_true_missings_runner.rb
#
# Each PoC runs in a forked subprocess so a segfault doesn't stop the whole suite.
# Set duration (seconds) via POC_DURATION=20.

DEFAULT_DURATION = (ENV["POC_DURATION"] || "20").to_f
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

def run_case_in_child(case_def, duration_s)
  deadline = now + duration_s
  case_def.run.call(deadline)
end

cases = [
  CaseDef.new(
    id: "io_buffer_set_string",
    description: "IO::Buffer#set_string (io_buffer_set_string) missing RB_GC_GUARD",
    run: lambda do |deadline|
      unless defined?(IO::Buffer)
        puts "SKIP: IO::Buffer not available"
        exit 0
      end

      GC.verify_compaction_references = true if GC.respond_to?(:verify_compaction_references=)
      GC.auto_compact = true if GC.respond_to?(:auto_compact=)
      begin
        GC.stress = :immediate
      rescue ArgumentError, TypeError
        GC.stress = true
      end

      Thread.new do
        loop do
          GC.compact if GC.respond_to?(:compact)
          GC.start(full_mark: true, immediate_sweep: true)
        end
      end

      class ToStrLarge
        def initialize(size, byte)
          @size = size
          @byte = byte
        end

        def to_str
          @byte * @size
        end
      end

      size = 4 * 1024 * 1024
      byte = "b"
      expected_byte = byte.ord
      sample_positions = [0, 1, 2, size / 3, size / 2, (size * 2) / 3, size - 1].uniq

      buf = IO::Buffer.new(size)

      Thread.new do
        loop do
          junk = []
          100.times { junk << ("x" * size) }
          junk.shuffle!
        end
      end

      while now < deadline
        buf.set_string(ToStrLarge.new(size, byte))
        out = buf.get_string(0, size)
        raise "unexpected output size: #{out.bytesize} != #{size}" unless out.bytesize == size
        sample_positions.each do |pos|
          raise "unexpected byte at #{pos}: #{out.getbyte(pos)}" unless out.getbyte(pos) == expected_byte
        end
      end

      puts "OK"
    end
  ),
  CaseDef.new(
    id: "arith_seq_inspect",
    description: "ArithmeticSequence#inspect (arith_seq_inspect) missing RB_GC_GUARD",
    run: lambda do |deadline|
      if GC.respond_to?(:verify_compaction_references=)
        GC.verify_compaction_references = true
      end
      if GC.respond_to?(:auto_compact=)
        GC.auto_compact = true
      end
      begin
        GC.stress = :immediate
      rescue ArgumentError, TypeError
        GC.stress = true
      end

      Thread.new do
        loop do
          GC.compact if GC.respond_to?(:compact)
          GC.start(full_mark: true, immediate_sweep: true)
        end
      end

      Thread.new do
        loop do
          junk = Array.new(200) { "x" * 1024 }
          junk.shuffle!
        end
      end

      while now < deadline
        1.step(10, 2).inspect
      end

      puts "OK"
    end
  )
]

max_id_len = cases.map { |c| c.id.length }.max || 0
any_fail = false

cases.each do |c|
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
      run_case_in_child(c, duration_s)
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
