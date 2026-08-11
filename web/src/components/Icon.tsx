import type { SVGProps } from 'react'

export type IconName =
  | 'overview' | 'globe' | 'shield' | 'server' | 'dns' | 'log' | 'settings'
  | 'plus' | 'arrow' | 'search' | 'filter' | 'more' | 'check' | 'warning'
  | 'info' | 'close' | 'upload' | 'terminal' | 'chevron' | 'copy' | 'menu'
  | 'logout' | 'refresh' | 'key' | 'clock' | 'trash' | 'link' | 'home'

type Props = SVGProps<SVGSVGElement> & { name: IconName; size?: number }

const paths: Record<IconName, React.ReactNode> = {
  overview: <><rect x="3" y="3" width="6" height="6" rx="1"/><rect x="15" y="3" width="6" height="6" rx="1"/><rect x="3" y="15" width="6" height="6" rx="1"/><rect x="15" y="15" width="6" height="6" rx="1"/></>,
  globe: <><circle cx="12" cy="12" r="9"/><path d="M3.5 9h17M3.5 15h17M12 3c2.2 2.4 3.3 5.4 3.3 9S14.2 18.6 12 21M12 3C9.8 5.4 8.7 8.4 8.7 12S9.8 18.6 12 21"/></>,
  shield: <><path d="M12 3 20 6v5.5c0 4.8-3.1 8-8 9.5-4.9-1.5-8-4.7-8-9.5V6l8-3Z"/><path d="m9.2 12 1.8 1.8 3.9-4"/></>,
  server: <><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01M11 7h7M11 17h7"/></>,
  dns: <><circle cx="12" cy="12" r="9"/><path d="M7.5 12h9M12 7.5v9"/><path d="M8.2 8.2 15.8 15.8M15.8 8.2l-7.6 7.6" opacity=".35"/></>,
  log: <><path d="M6 3h10l3 3v15H6z"/><path d="M16 3v4h4M9 11h6M9 15h6"/></>,
  settings: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.8 1.8 0 0 0 .4 2l.1.1-2.8 2.8-.1-.1a1.8 1.8 0 0 0-2-.4 1.8 1.8 0 0 0-1.1 1.7V21h-4v-.1A1.8 1.8 0 0 0 8.8 19a1.8 1.8 0 0 0-2 .4l-.1.1-2.8-2.8.1-.1a1.8 1.8 0 0 0 .4-2A1.8 1.8 0 0 0 2.7 13H2V9h.7a1.8 1.8 0 0 0 1.7-1.1 1.8 1.8 0 0 0-.4-2l-.1-.1L6.7 3l.1.1a1.8 1.8 0 0 0 2 .4A1.8 1.8 0 0 0 9.9 2h4a1.8 1.8 0 0 0 1.1 1.5 1.8 1.8 0 0 0 2-.4l.1-.1 2.8 2.8-.1.1a1.8 1.8 0 0 0-.4 2A1.8 1.8 0 0 0 21.1 9h.9v4h-.9a1.8 1.8 0 0 0-1.7 2Z"/></>,
  plus: <path d="M12 5v14M5 12h14"/>,
  arrow: <path d="M5 12h14M14 7l5 5-5 5"/>,
  search: <><circle cx="10.5" cy="10.5" r="6.5"/><path d="m15.5 15.5 4 4"/></>,
  filter: <path d="M4 6h16M7 12h10M10 18h4"/>,
  more: <><circle cx="5" cy="12" r=".8" fill="currentColor" stroke="none"/><circle cx="12" cy="12" r=".8" fill="currentColor" stroke="none"/><circle cx="19" cy="12" r=".8" fill="currentColor" stroke="none"/></>,
  check: <path d="m5 12 4.2 4.2L19 6.5"/>,
  warning: <><path d="m12 3 9 17H3L12 3Z"/><path d="M12 9v5M12 17.5h.01"/></>,
  info: <><circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/></>,
  close: <path d="m6 6 12 12M18 6 6 18"/>,
  upload: <><path d="M12 16V4M7 9l5-5 5 5"/><path d="M4 15v5h16v-5"/></>,
  terminal: <><path d="m5 7 4 4-4 4M11 17h8"/><rect x="2.5" y="3.5" width="19" height="17" rx="2.5"/></>,
  chevron: <path d="m9 6 6 6-6 6"/>,
  copy: <><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h3"/></>,
  menu: <path d="M4 7h16M4 12h16M4 17h16"/>,
  logout: <><path d="M10 5H4v14h6M14 8l4 4-4 4M8 12h10"/></>,
  refresh: <><path d="M20 7v5h-5M4 17v-5h5"/><path d="M18.3 10A7 7 0 0 0 6 6.5L4 9M5.7 14A7 7 0 0 0 18 17.5l2-2.5"/></>,
  key: <><circle cx="8" cy="12" r="4"/><path d="M12 12h9M17 12v3M20 12v2"/></>,
  clock: <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3.5 2"/></>,
  trash: <><path d="M4 7h16M9 3h6l1 4M7 7l1 14h8l1-14M10 11v6M14 11v6"/></>,
  link: <><path d="M9.5 14.5 8 16a4 4 0 0 1-5.7-5.7l3-3A4 4 0 0 1 11 7"/><path d="m14.5 9.5 1.5-1.5a4 4 0 0 1 5.7 5.7l-3 3A4 4 0 0 1 13 17M8 12h8"/></>,
  home: <><path d="m3 11 9-8 9 8"/><path d="M5 10v11h14V10M9 21v-7h6v7"/></>,
}

export function Icon({ name, size = 20, ...props }: Props) {
  return (
    <svg
      aria-hidden="true"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.35"
      strokeLinecap="round"
      strokeLinejoin="round"
      {...props}
    >
      {paths[name]}
    </svg>
  )
}
