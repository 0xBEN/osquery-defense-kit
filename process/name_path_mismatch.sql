SELECT p.name,
    f.filename,
    p.path,
    p.cmdline
FROM processes p
    JOIN file f ON p.path = f.path
WHERE SUBSTR(f.filename, 0, 8) != SUBSTR(p.name, 0, 8)
AND NOT (p.name='gjs' AND filename='gjs-console')
AND NOT (p.name='gnome-character' AND filename='gjs-console')
AND NOT (p.name='mysqld' AND filename='mariadbd')
AND NOT (p.name='tmux:client' AND filename='tmux')
AND NOT (p.name='tmux:server' AND filename='tmux')
AND NOT (p.name LIKE 'clangd:%' AND filename='clangd')
AND NOT (p.name='nix-daemon' AND filename='nix')
AND NOT (p.name='systemd-udevd' AND filename='udevadm')
AND NOT (p.name LIKE 'npm%' AND filename='node')
AND NOT (p.name='GUI Thread' AND filename='resolve')
AND NOT (p.name='X' AND filename='Xorg')
AND NOT p.path LIKE '/nix/store/%/bin/bash'
AND NOT p.path LIKE '/usr/bin/python3%'
AND NOT filename IN (
    'bash',
    'chrome',
    'dash',
    'electron',
    'firefox',
    'ruby',
    'sh',
    'slack',
    'systemd',
    'thunderbird'
)