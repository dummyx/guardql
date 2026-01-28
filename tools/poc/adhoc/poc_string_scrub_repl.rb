# Ad-hoc PoC (moved from repo root).

GC.verify_compaction_references = true if GC.respond_to?(:verify_compaction_references=)
GC.auto_compact = true if GC.respond_to?(:auto_compact=)
begin
  GC.stress = :immediate
rescue ArgumentError, TypeError
  GC.stress = true
end

repl = "X"

invalid = ("\xF0\x28\x8C\x28" * 1024).force_encoding("UTF-8")

loop do
  invalid.scrub(repl)
end
