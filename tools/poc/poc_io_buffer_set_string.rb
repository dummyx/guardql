#!/usr/bin/env ruby
# Stress IO::Buffer#set_string with GC compaction during nogvl memmove.

require_relative "poc_utils"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "10").to_i
size = (ENV["POC_SIZE"] || "2097152").to_i # 2MB default, >= IO_BUFFER_BLOCKING_SIZE

buf = IO::Buffer.new(size)

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    str = "A" * size
    buf.set_string(str, 0, str.bytesize, 0)
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 100).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
