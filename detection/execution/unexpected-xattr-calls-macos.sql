-- Detect unusual calls to xattr, used to remove filesystem attributes
--
-- false positives:
--   * none observed, but they are expected
--
-- interval: 300
-- platform: darwin
-- tags: process events
SELECT
  -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.pid AS p0_pid,
  pe.euid AS p0_euid,
  s.authority AS p0_authority,
  -- Parent
  pe.parent AS p1_pid,
  p1.cgroup_path AS p1_cgroup,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH(COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  pe_sig1.authority AS p1_authority,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  COALESCE(p1_p2.cgroup_path, pe1_p2.cgroup_path) AS p2_cgroup,
  TRIM(COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)) AS p2_cmd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(p1_p2_hash.path, pe1_p2_hash.path, pe1_pe2_hash.path) AS p2_hash,
  REGEX_MATCH(COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path), '.*/(.*)', 1) AS p2_name,
  COALESCE(p1_p2_sig.authority, pe1_p2_sig.authority, pe1_pe2_sig.authority) AS p2_authority,
  -- Exception key
  REGEX_MATCH (pe.path, '.*/(.*)', 1) || ',' || MIN(pe.euid, 500) || ',' || REGEX_MATCH(COALESCE(p1.path, pe1.path), '.*/(.*)', 1) || ',' || REGEX_MATCH(COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path), '.*/(.*)', 1) AS exception_key
FROM
  process_events pe, uptime
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN signature s ON pe.path = s.path
  -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
  LEFT JOIN signature pe_sig1 ON pe1.path = pe_sig1.path
  -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path

  LEFT JOIN signature p1_p2_sig ON p1_p2.path = p1_p2_sig.path
  LEFT JOIN signature pe1_p2_sig ON pe1_p2.path = pe1_p2_sig.path
  LEFT JOIN signature pe1_pe2_sig ON pe1_pe2.path = pe1_pe2_sig.path
WHERE
  pe.time > (strftime('%s', 'now') -300)
  AND pe.status = 0
  AND pe.cmdline != ''
  AND pe.cmdline IS NOT NULL
  AND pe.status == 0
  AND pe.path = '/usr/bin/xattr'
  AND p0_cmd NOT IN (
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Library/LoginItems/1Password Launcher.app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/XPCServices/OP Updater Service.xpc',
    '/usr/bin/xattr -r -d com.apple.quarantine /Applications/1Password.app',
    '/usr/bin/xattr -d -r com.apple.quarantine /Applications/iTerm.app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/XPCServices/OP Updater Service.xpc/Contents/Helpers/1Password Updater.app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Frameworks/1Password Helper.app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Frameworks/1Password Helper (GPU).app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Frameworks/1Password Helper (Plugin).app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Frameworks/1Password Helper (Renderer).app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/Keybase.app',
    '/usr/bin/xattr -d com.apple.quarantine /Applications/1Password.app/Contents/Library/LoginItems/1Password Browser Helper.app',
    'xattr -d -r com.apple.quarantine /Applications/Google Chrome.app'
  )
  AND NOT (
    pe.euid > 500
    AND p0_cmd LIKE '%xattr -l %'
  )
  AND NOT (
    pe.euid > 500
    AND p0_cmd LIKE '%xattr -p com.apple.quarantine %'
  )
  AND NOT (
    pe.euid > 500
    AND p0_cmd LIKE '%xattr -p com.apple.metadata:kMDItemAlternateNames %'
  )
  AND NOT (
    pe.euid > 500
    AND p0_cmd LIKE '/usr/bin/xattr -w com.apple.metadata:kMDItemAlternateNames %'
  )
  AND NOT (
    pe.euid > 500
    AND p0_cmd = '/usr/bin/xattr -h'
    AND p1_cmd LIKE '%homebrew%'
  )
  AND p0_cmd NOT LIKE '/usr/bin/xattr -w com.apple.quarantine 0002;%'
  AND p0_cmd NOT LIKE '/usr/bin/xattr -w com.apple.quarantine 0181;%'
GROUP BY
  pe.pid