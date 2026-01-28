#!/usr/bin/env ruby
# Stress String#unpack (pack_unpack_internal) under GC compaction.

require_relative "poc_utils"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "10").to_i
fmt_len = (ENV["POC_FMT_LEN"] || "2000").to_i

fmt = "A" * fmt_len
str = "x" * fmt_len

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    str.unpack(fmt)
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 100).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
