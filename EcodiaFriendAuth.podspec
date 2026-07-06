require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name = 'EcodiaFriendAuth'
  s.version = package['version']
  s.summary = package['description']
  s.license = package['license']
  s.homepage = 'https://ecodia.au'
  s.author = 'Ecodia'
  s.source = { :git => 'https://ecodia.au', :tag => s.version.to_s }
  s.source_files = 'ios/Sources/**/*.{swift,h,m,c,cc,mm,cpp}'
  s.ios.deployment_target = '15.0'
  s.dependency 'Capacitor'
  s.swift_version = '5.9'
end
