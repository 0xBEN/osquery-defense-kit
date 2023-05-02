-- Unexpected programs communicating over HTTPS (state-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net often
-- platform: macos
SELECT pos.protocol,
  pos.local_port,
  pos.remote_port,
  pos.remote_address,
  pos.local_port,
  pos.local_address,
  CONCAT (
    MIN(p0.euid, 500),
    ',',
    pos.protocol,
    ',',
    MIN(pos.remote_port, 32768),
    ',',
    REGEX_MATCH (p0.path, '.*/(.*?)$', 1),
    ',',
    p0.name,
    ',',
    s.authority,
    ',',
    s.identifier
  ) AS exception_key,
  CONCAT (
    MIN(p0.euid, 500),
    ',',
    pos.protocol,
    ',',
    MIN(pos.remote_port, 32768),
    ',',
    REGEX_MATCH (p0.path, '.*/(.*?)$', 1),
    ',',
    p0.name,
    ',',
    MIN(f.uid, 500),
    'u,',
    MIN(f.gid, 500),
    'g'
  ) AS alt_exception_key,
  CONCAT (s.authority, ',', s.identifier) AS id_exception_key,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  s.authority AS p0_sauth,
  s.identifier AS p0_sid,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM process_open_sockets pos
  LEFT JOIN processes p0 ON pos.pid = p0.pid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN signature s ON p0.path = s.path
WHERE pos.protocol > 0
  AND NOT (
    pos.remote_port IN (53, 443)
    AND pos.protocol IN (6, 17)
  )
  AND pos.remote_address NOT IN (
    '0.0.0.0',
    '127.0.0.1',
    '::ffff:127.0.0.1',
    '::1',
    '::'
  )
  AND pos.remote_address NOT LIKE 'fe80:%'
  AND pos.remote_address NOT LIKE '127.%'
  AND pos.remote_address NOT LIKE '192.168.%'
  AND pos.remote_address NOT LIKE '172.1%'
  AND pos.remote_address NOT LIKE '172.2%'
  AND pos.remote_address NOT LIKE '172.30.%'
  AND pos.remote_address NOT LIKE '172.31.%'
  AND pos.remote_address NOT LIKE '::ffff:172.%'
  AND pos.remote_address NOT LIKE '10.%'
  AND pos.remote_address NOT LIKE '::ffff:10.%'
  AND pos.remote_address NOT LIKE 'fc00:%'
  AND pos.remote_address NOT LIKE 'fdfd:%'
  AND pos.state != 'LISTEN' -- Ignore most common application paths
  AND p0.path NOT LIKE '/Library/Apple/System/Library/%'
  AND p0.path NOT LIKE '/Library/Application Support/%/Contents/%'
  AND p0.path NOT LIKE '/System/Applications/%'
  AND p0.path NOT LIKE '/System/Library/%'
  AND p0.path NOT LIKE '/System/%'
  AND p0.path NOT LIKE '/usr/libexec/%'
  AND p0.path NOT LIKE '/usr/sbin/%' -- Apple programs running from weird places, like the UpdateBrainService
  AND NOT (
    s.identifier LIKE 'com.apple.%'
    AND s.authority = 'Software Signing'
  )
  AND NOT exception_key IN (
    "500,17,8801,zoom.us,zoom.us,Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3),us.zoom.xos",
    '500,17,8801,zoom.us,zoom.us,Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3),us.zoom.xos',
    '500,6,22,Cyberduck,Cyberduck,Developer ID Application: David Kocher (G69SCX94XU),ch.sudo.cyberduck',
    '500,6,22,goland,goland,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3),com.jetbrains.goland',
    '500,6,32000,Spotify Helper,Spotify Helper,Developer ID Application: Spotify (2FNC3A47ZF),com.spotify.client.helper',
    '500,6,32768,IPNExtension,IPNExtension,Apple Mac OS Application Signing,io.tailscale.ipn.macos.network-extension',
    '500,6,4070,Spotify,Spotify,Developer ID Application: Spotify (2FNC3A47ZF),com.spotify.client',
    '500,6,5091,ZoomPhone,ZoomPhone,Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3),us.zoom.ZoomPhone',
    '500,6,8009,Spotify Helper,Spotify Helper,Developer ID Application: Spotify (2FNC3A47ZF),com.spotify.client.helper',
    '500,6,80,Arc Helper,Arc Helper,Developer ID Application: The Browser Company of New York Inc. (S6N382Y83G),company.thebrowser.browser.helper',
    '500,6,80,Code Helper (Plugin),Code Helper (Plugin),Developer ID Application: Microsoft Corporation (UBF8T346G9),com.github.Electron.helper',
    '500,6,80,Code - Insiders Helper (Plugin),Code - Insiders Helper (Plugin),Developer ID Application: Microsoft Corporation (UBF8T346G9),com.github.Electron.helper',
    '500,6,80,com.docker.backend,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R),com.docker',
    '500,6,80,Creative Cloud UI Helper,Creative Cloud UI Helper,Developer ID Application: Adobe Inc. (JQ525L2MZD),com.adobe.acc.HEXHelper',
    '500,6,80,firefox,firefox,Developer ID Application: Mozilla Corporation (43AQ936H96),org.mozilla.firefox',
    '500,6,80,IPNExtension,IPNExtension,Apple Mac OS Application Signing,io.tailscale.ipn.macos.network-extension',
    '500,6,80,Jabra Direct,Jabra Direct,Developer ID Application: GN Audio AS (55LV32M29R),com.jabra.directonline',
    '500,6,80,ksfetch,ksfetch,Developer ID Application: Google LLC (EQHXZ8M8AV),ksfetch',
    '500,6,80,launcher-Helper,launcher-Helper,Developer ID Application: Mojang AB (HR992ZEAE6),com.mojang.mclauncher.helper',
    '500,6,80,Snagit 2023,Snagit 2023,Developer ID Application: TechSmith Corporation (7TQL462TU8),com.TechSmith.Snagit2023',
    '500,6,80,SnagitHelper2020,SnagitHelper2020,Apple Mac OS Application Signing,com.techsmith.snagit.capturehelper2020',
    '500,6,80,Spotify,Spotify,Developer ID Application: Spotify (2FNC3A47ZF),com.spotify.client',
    '500,6,80,thunderbird,thunderbird,Developer ID Application: Mozilla Corporation (43AQ936H96),org.mozilla.thunderbird',
    '500,6,993,Mimestream,Mimestream,Developer ID Application: Mimestream, LLC (P2759L65T8),com.mimestream.Mimestream',
    '500,6,993,thunderbird,thunderbird,Developer ID Application: Mozilla Corporation (43AQ936H96),org.mozilla.thunderbird'
  ) -- Useful for unsigned binaries
  AND NOT alt_exception_key IN (
    '500,6,22,ssh,ssh,500u,20g',
    '500,6,80,copilot-agent-macos-arm64,copilot-agent-macos-arm64,500u,20g',
    '500,6,22,ssh,ssh,500u,80g',
    '500,6,3307,cloud-sql-proxy,cloud-sql-proxy,500u,20g'
  )
  AND NOT (
    exception_key LIKE '500,6,%,syncthing,syncthing,,syncthing'
    AND remote_port > 1024
  )
  AND NOT (
    alt_exception_key = '500,6,80,main,main,500u,20g'
    AND p0.path LIKE '/var/folders/%/T/go-build%/b001/exe/main'
  ) -- Known Web Browsers
  AND NOT (
    (
      pos.remote_port = 80
      OR pos.remote_port > 5000
    )
    AND id_exception_key IN (
      'Developer ID Application: Brave Software, Inc. (KL8N8XSYF4),com.brave.Browser.helper',
      'Developer ID Application: Google LLC (EQHXZ8M8AV),com.google.Chrome.helper',
      'Developer ID Application: Microsoft Corporation (UBF8T346G9),com.microsoft.edgemac.helper',
      'Developer ID Application: Mozilla Corporation (43AQ936H96),org.mozilla.firefox',
      'Developer ID Application: Mozilla Corporation (43AQ936H96),org.mozilla.firefoxdeveloperedition',
      'Developer ID Application: Opera Software AS (A2P9LX4JPN),com.operasoftware.Opera.helper',
      'Developer ID Application: The Browser Company of New York Inc. (S6N382Y83G),company.thebrowser.browser.helper'
    )
  )
GROUP BY p0.cmdline