import { SvgIcon, type SvgIconProps } from '@mui/material';

// The rail's own line icons (PO decision Q-47: the arrangement is reproduced, nothing is copied). Simple strokes on a
// 24-unit grid, drawn in the current text colour so the selected item's colour carries over.

export type IconName =
  | 'overview'
  | 'traffic'
  | 'policies'
  | 'platforms'
  | 'notice'
  | 'health'
  | 'admin'
  | 'menu'
  | 'search';

const PATHS: Record<IconName, React.ReactNode> = {
  overview: (
    <>
      <rect x="3.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="3.5" width="7" height="7" rx="1.5" />
      <rect x="3.5" y="13.5" width="7" height="7" rx="1.5" />
      <rect x="13.5" y="13.5" width="7" height="7" rx="1.5" />
    </>
  ),
  traffic: <path d="M4 8h14M14.5 4.5 18 8l-3.5 3.5M20 16H6M9.5 12.5 6 16l3.5 3.5" />,
  policies: <path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" />,
  platforms: <path d="M12 3.5l8.5 4.5-8.5 4.5L3.5 8zM3.5 12.5l8.5 4.5 8.5-4.5M3.5 16.5l8.5 4.5 8.5-4.5" />,
  notice: <path d="M6 3.5h8.5l3.5 3.5v13.5H6zM14 3.5V7.5h4M9 12h6M9 16h6" />,
  health: <path d="M3 12h4l2.5-5.5 4 11 2.5-5.5H21" />,
  admin: (
    <>
      <path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1" />
      <circle cx="15" cy="6" r="2" />
      <circle cx="9" cy="12" r="2" />
      <circle cx="17" cy="18" r="2" />
    </>
  ),
  menu: <path d="M4 6.5h16M4 12h16M4 17.5h16" />,
  search: (
    <>
      <circle cx="10.5" cy="10.5" r="6" />
      <path d="M15 15l5 5" />
    </>
  ),
};

export function RailIcon({ name, ...props }: { name: IconName } & SvgIconProps) {
  return (
    <SvgIcon {...props} viewBox="0 0 24 24">
      <g fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round">
        {PATHS[name]}
      </g>
    </SvgIcon>
  );
}
