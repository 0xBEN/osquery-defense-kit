-- Find unexpected hidden files in a users Library directory
--
-- references:
--   * https://www.sentinelone.com/blog/xcsset-malware-update-macos-threat-actors-prepare-for-life-without-python/
--
-- false positives:
--   * programs which create new Library directories
--
-- tags: persistent state filesystem
-- platform: darwin
SELECT
  file.path,
  file.type,
  file.size,
  file.mtime,
  file.uid,
  file.ctime,
  file.gid,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    file.path LIKE '/Users/%/Library/%%/.%/%'
    OR file.path LIKE '/Users/%/Library/.%/%'
    OR file.path LIKE '/home/%/Library/%%/.%/.%'
  )
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
