# Ad-hoc PoC (moved from repo root).

require "stringio"
require "zlib"

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

payload = "a" * (4 * 1024 * 1024)
io = StringIO.new
gz = Zlib::GzipWriter.new(io)
gz.write(payload)
gz.close
member = io.string

compressed = member * 8
expected_len = payload.bytesize * 8
sample_positions = [
  0,
  1,
  2,
  expected_len / 3,
  expected_len / 2,
  (expected_len * 2) / 3,
  expected_len - 1
].uniq

loop do
  data_io = StringIO.new(compressed)
  out = Zlib::GzipReader.zcat(data_io)
  raise "unexpected output size: #{out.bytesize} != #{expected_len}" unless out.bytesize == expected_len
  sample_positions.each do |pos|
    raise "unexpected byte at #{pos}: #{out.getbyte(pos)}" unless out.getbyte(pos) == 97
  end
end
