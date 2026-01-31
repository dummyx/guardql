#!/usr/bin/env ruby
# Stress Bug::Struct.new_duplicate_under under GC compaction.

require_relative "poc_utils"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

begin
  require "-test-/struct"
rescue LoadError
  warn "SKIP: missing -test-/struct"
  exit 0
end

duration = (ENV["POC_SECONDS"] || "10").to_i

name = "S" * 1024
member = "m" * 1024

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    begin
      Bug::Struct.new_duplicate_under(name, member)
    rescue ArgumentError
      # Expected due to duplicate member names; still exercises the C path.
    end
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 100).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
