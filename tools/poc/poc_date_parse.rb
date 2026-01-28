#!/usr/bin/env ruby
# Stress Date._parse (date_parse.c / s3e) under GC compaction.

require_relative "poc_utils"
POC.add_build_load_path
date_lib = File.expand_path("../../ruby/ext/date/lib", __dir__)
$LOAD_PATH.unshift(date_lib) if Dir.exist?(date_lib)
require "date"

STDOUT.sync = true
Thread.report_on_exception = true

POC.setup_gc

duration = (ENV["POC_SECONDS"] || "10").to_i

base = "Tue, 2024-07-05 12:34:56 +0000"
noise = "x" * (ENV["POC_NOISE"] || "80").to_i
input = (base + noise)[0, 120]

gc_thread = POC.start_gc_hammer

iterations = 0
begin
  POC.run_for(duration) do
    Date._parse(input)
    iterations += 1
    puts "iterations=#{iterations}" if (iterations % 100).zero?
  end
ensure
  gc_thread.kill
end

puts "done iterations=#{iterations}"
