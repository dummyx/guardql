# Ad-hoc PoC (moved from repo root).

GC.verify_compaction_references = true if GC.respond_to?(:verify_compaction_references=)
GC.auto_compact = true if GC.respond_to?(:auto_compact=)
begin
  GC.stress = :immediate
rescue ArgumentError, TypeError
  GC.stress = true
end

n = 10_000
data = Array.new(n, 0)
expected = "\x00" * n

iterations = 0
loop do
  out = data.pack("w*")
  iterations += 1

  if out != expected
    $stderr.puts "mismatch at iteration=#{iterations}"
    $stderr.puts "out.bytesize=#{out.bytesize} expected.bytesize=#{expected.bytesize}"
    # show a small diff window
    (0...[out.bytesize, expected.bytesize].min).each do |i|
      next if out.getbyte(i) == 0
      $stderr.puts "first non-zero at i=#{i} byte=0x#{out.getbyte(i).to_s(16)}"
      break
    end
    exit 2
  end
end
