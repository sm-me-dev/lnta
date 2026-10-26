# typed: false
# frozen_string_literal: true

# Formula for LNTA (Linux Natural-Language Terminal Assistant)
class Lnta < Formula
  desc "Fast, kernel-sandboxed Linux natural-language terminal assistant"
  homepage "https://github.com/sm-me-dev/lnta"
  version "0.1.5"
  license "MIT"

  on_linux do
    if Hardware::CPU.intel?
      url "https://github.com/sm-me-dev/lnta/releases/download/v#{version}/lnta_#{version}_linux_amd64.tar.gz"
    elsif Hardware::CPU.arm?
      url "https://github.com/sm-me-dev/lnta/releases/download/v#{version}/lnta_#{version}_linux_arm64.tar.gz"
    end
  end

  def install
    bin.install "lnta"
  end

  test do
    assert_match "LNTA version", shell_output("#{bin}/lnta --version")
  end
end
