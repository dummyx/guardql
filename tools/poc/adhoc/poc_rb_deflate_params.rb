# Ad-hoc PoC (moved from repo root).

require "zlib"

d = Zlib::Deflate.new
d.params(Zlib::BEST_SPEED, Zlib::DEFAULT_STRATEGY)
d.finish
