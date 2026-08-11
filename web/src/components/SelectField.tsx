import * as Select from '@radix-ui/react-select'
import { Icon, type IconName } from './Icon'

export interface SelectOption {
  value: string
  label: string
  description?: string
  disabled?: boolean
}

interface Props {
  value: string
  options: SelectOption[]
  onChange: (value: string) => void
  placeholder?: string
  ariaLabel: string
  icon?: IconName
  disabled?: boolean
  className?: string
}

export function SelectField({ value, options, onChange, placeholder, ariaLabel, icon, disabled, className = '' }: Props) {
  const utility = className.split(/\s+/).includes('utility-select')
  const selected = options.find((option) => option.value === value)
  return (
    <Select.Root value={value || undefined} onValueChange={onChange} disabled={disabled}>
      <Select.Trigger className={`custom-select-trigger ${className}`} aria-label={ariaLabel}>
        {icon && <Icon name={icon} size={17} />}
        <Select.Value placeholder={placeholder}>{selected?.label}</Select.Value>
        <Select.Icon className="custom-select-caret"><Icon name="chevron" size={15} /></Select.Icon>
      </Select.Trigger>
      <Select.Portal>
        <Select.Content className={`custom-select-content ${utility ? 'utility-select-content' : ''}`} position="popper" align={utility ? 'end' : 'start'} sideOffset={8} collisionPadding={14} sticky="always">
          <Select.ScrollUpButton className="custom-select-scroll-button"><Icon name="chevron" size={14} /></Select.ScrollUpButton>
          <Select.Viewport className="custom-select-viewport">
            {options.map((option) => (
              <Select.Item className="custom-select-item" value={option.value} disabled={option.disabled} key={option.value}>
                <Select.ItemText>
                  <span className="custom-select-copy"><strong>{option.label}</strong>{option.description && <small>{option.description}</small>}</span>
                </Select.ItemText>
                <Select.ItemIndicator className="custom-select-check"><Icon name="check" size={15} weight="bold" /></Select.ItemIndicator>
              </Select.Item>
            ))}
          </Select.Viewport>
          <Select.ScrollDownButton className="custom-select-scroll-button custom-select-scroll-down"><Icon name="chevron" size={14} /></Select.ScrollDownButton>
        </Select.Content>
      </Select.Portal>
    </Select.Root>
  )
}
