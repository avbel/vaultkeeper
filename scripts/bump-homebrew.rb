#!/usr/bin/env ruby
# frozen_string_literal: true

# Rewrites the formula's version and its two sha256 lines from a release's SHA256SUMS.
#   scripts/bump-homebrew.rb <formula path> <version> <SHA256SUMS path>
# Each sha256 line follows the url of its architecture, so the digest is looked up by the
# tarball name in the line above it.

formula_path, version, sums_path = ARGV
abort "usage: #{$PROGRAM_NAME} <formula> <version> <SHA256SUMS>" unless formula_path && version && sums_path
abort "version must look like 1.2.3, got #{version}" unless version.match?(/\A\d+\.\d+\.\d+\z/)

sums = File.readlines(sums_path).to_h do |line|
  digest, name = line.split
  [name.delete_prefix("*"), digest]
end

lines = File.readlines(formula_path)
lines.map!.with_index do |line, index|
  if line.match?(/^\s*version "/)
    line.sub(/"[^"]*"/, %("#{version}"))
  elsif line.match?(/^\s*sha256 "/)
    triple = lines[index - 1][/vaultkeeper-v#\{version\}-([\w-]+)\.tar\.gz/, 1]
    abort "no url above line #{index + 1}" unless triple
    name = "vaultkeeper-v#{version}-#{triple}.tar.gz"
    digest = sums.fetch(name) { abort "#{name} is missing from #{sums_path}" }
    line.sub(/"[0-9a-f]{64}"/, %("#{digest}"))
  else
    line
  end
end
File.write(formula_path, lines.join)
