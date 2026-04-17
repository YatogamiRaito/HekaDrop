cask "hekadrop" do
  version "0.1.0"
  sha256 :no_check # İlk release sonrası gerçek hash ile değiştirilecek

  url "https://github.com/YatogamiRaito/HekaDrop/releases/download/v#{version}/HekaDrop-#{version}.dmg"
  name "HekaDrop"
  desc "Google Quick Share (Nearby Share) client for macOS — Rust"
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
