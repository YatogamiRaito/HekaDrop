cask "hekadrop" do
  version "0.4.0"
  sha256 "f2f2122e2e82b9af465fe3682c06aae45c0039cae789b2a239202aae3516b1ad"

  url "https://github.com/YatogamiRaito/HekaDrop/releases/download/v#{version}/HekaDrop-#{version}-macos.zip"
  name "HekaDrop"
  desc "Google Quick Share (Nearby Share) client — Rust, cross-platform"
  homepage "https://github.com/YatogamiRaito/HekaDrop"

  auto_updates false
  depends_on macos: ">= :big_sur"

  app "HekaDrop.app"

  uninstall quit:      "com.sourvice.hekadrop",
            launchctl: "com.sourvice.hekadrop"

  zap trash: [
    "~/Library/Application Support/HekaDrop",
    "~/Library/Logs/HekaDrop",
    "~/Library/LaunchAgents/com.sourvice.hekadrop.plist",
    "~/Library/Preferences/com.sourvice.hekadrop.plist",
  ]
end
