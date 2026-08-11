import type { Icon as PhosphorIcon, IconProps } from '@phosphor-icons/react'
import {
  ArrowRight,
  ArrowsClockwise,
  Certificate,
  Check,
  ClipboardText,
  Clock,
  Cloud,
  CloudArrowDown,
  Copy,
  Database,
  Desktop,
  DotsThree,
  DownloadSimple,
  Eye,
  FunnelSimple,
  GearSix,
  GlobeHemisphereWest,
  HardDrives,
  House,
  Info,
  Key,
  LinkSimple,
  List,
  LockKey,
  MagnifyingGlass,
  Moon,
  PencilSimple,
  Plus,
  ShieldCheck,
  SignOut,
  SquaresFour,
  Sun,
  TerminalWindow,
  Translate,
  Trash,
  UploadSimple,
  UserCircle,
  Warning,
  X,
  CaretRight,
} from '@phosphor-icons/react'

export type IconName =
  | 'overview' | 'globe' | 'shield' | 'server' | 'dns' | 'log' | 'settings'
  | 'plus' | 'arrow' | 'search' | 'filter' | 'more' | 'check' | 'warning'
  | 'info' | 'close' | 'upload' | 'terminal' | 'chevron' | 'copy' | 'menu'
  | 'logout' | 'refresh' | 'key' | 'clock' | 'trash' | 'link' | 'home'
  | 'edit' | 'language' | 'sun' | 'moon' | 'system' | 'user' | 'lock'
  | 'download' | 'eye' | 'certificate' | 'cloud-download' | 'database'

type Props = Omit<IconProps, 'name'> & { name: IconName; size?: number }

const icons: Record<IconName, PhosphorIcon> = {
  overview: SquaresFour,
  globe: GlobeHemisphereWest,
  shield: ShieldCheck,
  server: HardDrives,
  dns: Cloud,
  log: ClipboardText,
  settings: GearSix,
  plus: Plus,
  arrow: ArrowRight,
  search: MagnifyingGlass,
  filter: FunnelSimple,
  more: DotsThree,
  check: Check,
  warning: Warning,
  info: Info,
  close: X,
  upload: UploadSimple,
  terminal: TerminalWindow,
  chevron: CaretRight,
  copy: Copy,
  menu: List,
  logout: SignOut,
  refresh: ArrowsClockwise,
  key: Key,
  clock: Clock,
  trash: Trash,
  link: LinkSimple,
  home: House,
  edit: PencilSimple,
  language: Translate,
  sun: Sun,
  moon: Moon,
  system: Desktop,
  user: UserCircle,
  lock: LockKey,
  download: DownloadSimple,
  eye: Eye,
  certificate: Certificate,
  'cloud-download': CloudArrowDown,
  database: Database,
}

export function Icon({ name, size = 20, weight = 'regular', ...props }: Props) {
  const Component = icons[name]
  return <Component aria-hidden="true" size={size} weight={weight} {...props} />
}
