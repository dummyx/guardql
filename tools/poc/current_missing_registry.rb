#!/usr/bin/env ruby
# Builds a current missing-site registry from missing_guard_detail CSV output.

require "csv"
require "fileutils"
require "optparse"
require "set"

DEFAULT_DETAIL = "/tmp/guardql_ruby_missing_detail_after.csv"
DEFAULT_OUTPUT = "tools/poc/current_missing_registry.csv"

CONFIRMED = {
  "open_key_args" => "crash SIGSEGV in IO.read",
  "io_buffer_set_string" => "crash SIGSEGV in IO::Buffer#set_string",
  "rb_str_format_m" => "crash SIGSEGV in String#%",
  "arith_seq_inspect" => "crash/corruption in ArithmeticSequence#inspect",
  "append_method" => "corruption in Enumerator#inspect args",
  "str_transcode0" => "corruption in String#encode"
}.freeze

SCRIPT_ALIASES = {
  "deflate_run" => ["zlib_deflate_stream_compactfree", "zlib_deflate_inflate_compactfree"],
  "do_deflate" => ["zlib_deflate_stream_compactfree", "zlib_deflate_inflate_compactfree"],
  "inflate_run" => ["zlib_inflate_stream_compactfree", "zlib_deflate_inflate_compactfree"],
  "do_inflate" => ["zlib_inflate_stream_compactfree", "zlib_deflate_inflate_compactfree"],
  "location_format" => ["location_format_compactfree_check", "adhoc/location_format"],
  "rjit_str_simple_append" => ["rb_yjit_str_simple_append_compactfree"],
  "rb_reg_prepare_re" => ["rb_reg_prepare_re_match_compactfree"],
  "rb_execarg_parent_start1" => ["rb_execarg_parent_start1_tostr_compactfree"],
  "rb_gzreader_s_zcat" => ["rb_gzreader_s_zcat_compactfree"],
  "r_bytes1_buffered" => ["marshal_r_bytes1_buffered_compactfree"],
  "qpencode" => ["qpencode_compactfree"]
}.freeze

options = {
  detail: DEFAULT_DETAIL,
  output: DEFAULT_OUTPUT,
  repo_root: Dir.pwd
}

OptionParser.new do |opts|
  opts.banner = "usage: ruby tools/poc/current_missing_registry.rb [options]"
  opts.on("--detail PATH", "missing_guard_detail CSV input") { |v| options[:detail] = v }
  opts.on("--output PATH", "registry CSV output") { |v| options[:output] = v }
  opts.on("--repo-root PATH", "repository root") { |v| options[:repo_root] = v }
end.parse!

def runner_ids(path)
  return Set.new unless File.file?(path)

  text = File.read(path)
  ids = text.scan(/id:\s*"([^"]+)"/).flatten
  ids.concat(text.scan(/^\s*"([^"]+)"\s*=>/).flatten)
  ids.to_set
end

def tracked_paths(repo_root)
  output = IO.popen(["git", "ls-files", "tools/poc"], chdir: repo_root, &:read)
  output.lines.map(&:chomp).to_set
rescue SystemCallError
  Set.new
end

def script_index(repo_root)
  tracked = tracked_paths(repo_root)
  index = {}
  Dir.glob(File.join(repo_root, "tools/poc/{,adhoc/}poc_*.rb")).sort.each do |path|
    rel = path.delete_prefix("#{repo_root}/")
    id = rel.sub(%r{\Atools/poc/}, "").sub(/\.rb\z/, "").sub(%r{\Apoc_}, "")
    index[id] = { path: rel, tracked: tracked.include?(rel) }
  end
  index
end

def relative_location(uri)
  loc = uri.to_s.sub(%r{\Afile://}, "")
  loc.sub(%r{\A/home/x17/code_repo/xie-guard-jssst2025/ruby_orig/}, "ruby/")
end

def loc_line(loc)
  loc.split(":")[1] || ""
end

def site_id(function, variable, loc)
  file = loc.split(":").first
  line = loc_line(loc)
  [function, variable, file, line].join(":")
end

def choose_script(function, scripts)
  candidates = [function, "#{function}_compactfree", *SCRIPT_ALIASES.fetch(function, [])]
  candidates.each do |id|
    return [id, scripts[id]] if scripts[id]
  end
  nil
end

detail_path = File.expand_path(options[:detail], options[:repo_root])
abort "missing detail CSV: #{detail_path}" unless File.file?(detail_path)

repo_root = File.expand_path(options[:repo_root])
true_ids = runner_ids(File.join(repo_root, "tools/poc/poc_true_missings_runner.rb"))
candidate_ids = runner_ids(File.join(repo_root, "tools/poc/poc_missing_candidates_runner.rb"))
scripts = script_index(repo_root)

sites = {}
CSV.foreach(detail_path, headers: true) do |row|
  loc = relative_location(row["vloc"])
  key = [row["v"], row["f"], loc]
  sites[key] ||= {
    variable: row["v"],
    function: row["f"],
    location: loc,
    witness_kinds: Set.new,
    derivation_families: Set.new,
    derivation_names: Set.new,
    triggers: Set.new,
    pointer_names: Set.new
  }
  site = sites[key]
  site[:witness_kinds] << row["witness_kind"]
  site[:derivation_families] << row["derivation_family"]
  site[:derivation_names] << row["derivation_name"]
  site[:triggers] << row["trigger_name"]
  site[:pointer_names] << row["pointer_name"]
end

headers = %w[
  site_id variable function location witness_kinds derivation_families
  derivation_names triggers pointer_names poc_status poc_source poc_id
  runner script_path script_tracked evidence notes
]

rows = sites.values.sort_by { |s| [s[:location], s[:function], s[:variable]] }.map do |site|
  function = site[:function]
  status = nil
  source = nil
  poc_id = nil
  runner = nil
  script_path = nil
  script_tracked = nil
  evidence = ""
  notes = ""

  if CONFIRMED.key?(function)
    status = "confirmed"
    source = "true_runner"
    poc_id = function
    runner = "tools/poc/poc_true_missings_runner.rb"
    evidence = CONFIRMED.fetch(function)
  elsif true_ids.include?(function)
    status = "candidate"
    source = "true_runner"
    poc_id = function
    runner = "tools/poc/poc_true_missings_runner.rb"
  elsif candidate_ids.include?(function)
    status = "candidate"
    source = "candidate_runner"
    poc_id = function
    runner = "tools/poc/poc_missing_candidates_runner.rb"
  elsif (script = choose_script(function, scripts))
    status = "candidate"
    source = "standalone_script"
    poc_id = script[0]
    script_path = script[1][:path]
    script_tracked = script[1][:tracked] ? "yes" : "no"
    notes = script[1][:tracked] ? "" : "local untracked script available"
  else
    status = "needs_new_poc"
    source = "none"
    notes = "no runner case or standalone script found"
  end

  {
    "site_id" => site_id(function, site[:variable], site[:location]),
    "variable" => site[:variable],
    "function" => function,
    "location" => site[:location],
    "witness_kinds" => site[:witness_kinds].to_a.sort.join("|"),
    "derivation_families" => site[:derivation_families].to_a.sort.join("|"),
    "derivation_names" => site[:derivation_names].to_a.sort.join("|"),
    "triggers" => site[:triggers].to_a.sort.join("|"),
    "pointer_names" => site[:pointer_names].to_a.sort.join("|"),
    "poc_status" => status,
    "poc_source" => source,
    "poc_id" => poc_id,
    "runner" => runner,
    "script_path" => script_path,
    "script_tracked" => script_tracked,
    "evidence" => evidence,
    "notes" => notes
  }
end

output_path = File.expand_path(options[:output], repo_root)
FileUtils.mkdir_p(File.dirname(output_path)) unless Dir.exist?(File.dirname(output_path))
CSV.open(output_path, "w", write_headers: true, headers: headers) do |csv|
  rows.each { |row| csv << headers.map { |h| row[h] } }
end

counts = rows.group_by { |r| r["poc_status"] }.transform_values(&:size)
sources = rows.group_by { |r| r["poc_source"] }.transform_values(&:size)
present_functions = rows.map { |r| r["function"] }.to_set
not_current = CONFIRMED.keys.reject { |function| present_functions.include?(function) }
warn "wrote #{rows.size} sites to #{output_path}"
warn "status counts: #{counts.sort.to_h}"
warn "source counts: #{sources.sort.to_h}"
warn "known confirmed not in current detail: #{not_current.join(", ")}" unless not_current.empty?
