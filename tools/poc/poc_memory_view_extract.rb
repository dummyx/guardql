#!/usr/bin/env ruby
# Stress MemoryViewTestUtils.extract_item_members (memory_view_extract_item_members).

require_relative "poc_utils"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

begin
  require "-test-/memory_view"
rescue LoadError
  warn "SKIP: missing -test-/memory_view"
  exit 0
end

duration = (ENV["POC_SECONDS"] || "10").to_i

# Use a simple format with fixed-size fields.
format = "II"
str = ("\x01\x00\x00\x00" * 2)

if str.bytesize < 8
  raise "unexpected string size"
end

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    MemoryViewTestUtils.extract_item_members(str, format)
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 100).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
