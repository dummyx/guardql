#!/usr/bin/env ruby
# Stress String#crypt with GC compaction (rb_str_crypt).

require_relative "poc_utils"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "10").to_i
salt = "ab"

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    ("pass" + iterations.to_s).crypt(salt)
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 1000).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
