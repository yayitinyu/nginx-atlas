# Nginx Atlas design system

The implementation follows the accepted dashboard, deployment drawer, and mobile concepts generated for this project.

## Visual direction

- Background: true graphite black (`#080b0a`) with a fixed, low-opacity grain layer.
- Surfaces: open layout first; framed surfaces use concentric 18/14 px radii and two low-contrast hairlines.
- Type: Geist-compatible grotesk stack, warm silver body text, compressed tracking for display headings.
- Accent: cool mint (`#68dfac`) for actions and healthy state; amber (`#f1b94b`) only for renewal risk; coral red only for errors.
- Icons: custom 1.35 px outline SVGs with round caps and joins. No emoji or mixed icon families.
- Motion: 560–760 ms physical easing (`cubic-bezier(.22,.8,.2,1)`), transform/opacity only, with reduced-motion support.

## Container and responsive rules

- Desktop uses a detached 216 px navigation rail and an asymmetrical main/health-rail split.
- Tables remain tables on desktop. Mobile rows preserve column hierarchy in a compact stacked list rather than becoming unrelated cards.
- The creation flow is a right-side drawer on desktop and a full-width sheet on mobile.
- Mobile controls have a minimum 44 px touch target and use `min-height: 100dvh`.

## Core component families

- `AppShell`, `NavigationRail`, `MobileBar`
- `Bezel`, `StatusStrip`, `DomainTable`, `NodeRail`, `ActivityFeed`
- `ActionButton`, `IconButton`, `StatusDot`, `SegmentedControl`
- `DomainDrawer`, `Field`, `SelectField`, `CertificateUpload`, `ConfigPreview`
- `LoginGate`, `ToastRegion`, `ConfirmDialog`

The app UI, icons, controls, tables, and configuration previews are code-native. Concept images are design references only.
