#!/usr/bin/env ruby
# frozen_string_literal: true

# Rewrites a formula's or cask's version and its sha256 lines from a release's SHA256SUMS.
#   scripts/bump-homebrew.rb <formula or cask path> <version> <SHA256SUMS path>
# Each sha256 line is paired with the release asset its url names: in a formula the url sits on
# the line above it (one per architecture), in a cask the single url follows it.

formula_path, version, sums_path = ARGV
abort "usage: #{$PROGRAM_NAME} <formula or cask> <version> <SHA256SUMS>" unless formula_path && version && sums_path
abort "version must look like 1.2.3, got #{version}" unless version.match?(/\A\d+\.\d+\.\d+\z/)

ASSET = %r{/releases/download/v\#\{version\}/([^"/]+)"}

sums = File.readlines(sums_path).to_h do |line|
  digest, name = line.split
  [name.delete_prefix("*"), digest]
end

def asset_near(lines, index)
  [index - 1, index + 1, index + 2, index + 3].each do |near|
    next if near.negative? || near >= lines.length

    name = lines[near][ASSET, 1]
    return name if name
  end
  nil
end

lines = File.readlines(formula_path)
lines.map!.with_index do |line, index|
  if line.match?(/^\s*version "/)
    line.sub(/"[^"]*"/, %("#{version}"))
  elsif line.match?(/^\s*sha256 "/)
    template = asset_near(lines, index)
    abort "no release url next to line #{index + 1}" unless template
    name = template.gsub('#{version}', version)
    digest = sums.fetch(name) { abort "#{name} is missing from #{sums_path}" }
    line.sub(/"[0-9a-f]{64}"/, %("#{digest}"))
  else
    line
  end
end
File.write(formula_path, lines.join)
