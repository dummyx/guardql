#!/usr/bin/env ruby
# Stress IO::Buffer#set_string with GC compaction during nogvl memmove.

require_relative "poc_utils"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "20").to_i
size = (ENV["POC_SIZE"] || "4194304").to_i # 4MB default, >= IO_BUFFER_BLOCKING_SIZE

buf = IO::Buffer.new(size)

gc_thread = POC.start_gc_hammer

Thread.new do
  loop do
    junk = []
    100.times { junk << ("x" * size) }
    junk.shuffle!
  end
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

fill = (ENV["POC_FILL"] || "b")
expected_byte = fill.ord
sample_positions = [0, 1, 2, size / 3, size / 2, (size * 2) / 3, size - 1].uniq

iterations = 0
begin
  POC.run_for(duration) do
    buf.set_string(POCToStrLarge.new(size, fill))
    out = buf.get_string(0, size)
    raise "unexpected output size: #{out.bytesize} != #{size}" unless out.bytesize == size
    sample_positions.each do |pos|
      raise "unexpected byte at #{pos}: #{out.getbyte(pos)}" unless out.getbyte(pos) == expected_byte
    end
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 100).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
