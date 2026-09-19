import React, { useState, useRef, useEffect, createContext, useContext } from 'react';
import { cn } from '../../utils/cn';

interface DropdownContextType {
  isOpen: boolean;
  setIsOpen: React.Dispatch<React.SetStateAction<boolean>>;
  closeDropdown: () => void;
  focusedIndex: number;
  setFocusedIndex: React.Dispatch<React.SetStateAction<number>>;
  itemCount: React.MutableRefObject<number>;
}

const DropdownContext = createContext<DropdownContextType | undefined>(undefined);

export interface DropdownProps {
  children: React.ReactNode;
  className?: string;
}

export const Dropdown: React.FC<DropdownProps> = ({ children, className }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [focusedIndex, setFocusedIndex] = useState(-1);
  const itemCount = useRef(0);
  const containerRef = useRef<HTMLDivElement>(null);

  const closeDropdown = () => {
    setIsOpen(false);
    setFocusedIndex(-1);
  };

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        closeDropdown();
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen]);

  return (
    <DropdownContext.Provider
      value={{
        isOpen,
        setIsOpen,
        closeDropdown,
        focusedIndex,
        setFocusedIndex,
        itemCount,
      }}
    >
      <div ref={containerRef} className={cn('relative inline-block text-left', className)}>
        {children}
      </div>
    </DropdownContext.Provider>
  );
};

export interface DropdownTriggerProps {
  children: React.ReactElement<{
    onClick?: React.MouseEventHandler;
    'aria-expanded'?: boolean;
    'aria-haspopup'?: boolean | 'menu';
  }>;
}

export const DropdownTrigger: React.FC<DropdownTriggerProps> = ({ children }) => {
  const context = useContext(DropdownContext);
  if (!context) throw new Error('DropdownTrigger must be used within a Dropdown');
  const { isOpen, setIsOpen } = context;

  return React.cloneElement(children, {
    onClick: (e: React.MouseEvent) => {
      children.props.onClick?.(e);
      setIsOpen(!isOpen);
    },
    'aria-expanded': isOpen,
    'aria-haspopup': 'menu',
  });
};

export type DropdownAlign = 'left' | 'right';

export interface DropdownMenuProps extends React.HTMLAttributes<HTMLDivElement> {
  align?: DropdownAlign;
  width?: string;
}

export const DropdownMenu: React.FC<DropdownMenuProps> = ({
  children,
  align = 'right',
  width = 'w-56',
  className,
  ...props
}) => {
  const context = useContext(DropdownContext);
  if (!context) throw new Error('DropdownMenu must be used within a Dropdown');
  const { isOpen, closeDropdown, setFocusedIndex, itemCount } = context;
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        closeDropdown();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setFocusedIndex((prev) => (prev < itemCount.current - 1 ? prev + 1 : 0));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setFocusedIndex((prev) => (prev > 0 ? prev - 1 : itemCount.current - 1));
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, closeDropdown, itemCount, setFocusedIndex]);

  if (!isOpen) return null;

  return (
    <div
      ref={menuRef}
      role="menu"
      aria-orientation="vertical"
      className={cn(
        'absolute z-50 mt-1.5 p-1 bg-surface-elevated border border-border rounded-control shadow-popover',
        'animate-in fade-in zoom-in-95 duration-100 focus:outline-none',
        align === 'right' ? 'right-0' : 'left-0',
        width,
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
};

export interface DropdownItemProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  icon?: React.ReactNode;
  active?: boolean;
  destructive?: boolean;
}

export const DropdownItem = React.forwardRef<HTMLButtonElement, DropdownItemProps>(
  ({ className, icon, active = false, destructive = false, onClick, children, ...props }, ref) => {
    const context = useContext(DropdownContext);
    if (!context) throw new Error('DropdownItem must be used within a Dropdown');
    const { closeDropdown } = context;

    return (
      <button
        ref={ref}
        type="button"
        role="menuitem"
        onClick={(e) => {
          onClick?.(e);
          closeDropdown();
        }}
        className={cn(
          'w-full flex items-center gap-2 px-2.5 py-1.5 text-xs font-sans rounded-control text-left transition-colors cursor-pointer select-none',
          'focus:outline-none focus:bg-surface-secondary',
          active
            ? 'bg-primary-subtle text-primary font-medium'
            : destructive
            ? 'text-danger hover:bg-danger-surface'
            : 'text-foreground hover:bg-surface-secondary',
          className
        )}
        {...props}
      >
        {icon && <span className="flex-shrink-0 w-3.5 h-3.5 inline-flex items-center">{icon}</span>}
        <span className="flex-1 truncate">{children}</span>
      </button>
    );
  }
);
DropdownItem.displayName = 'DropdownItem';

export const DropdownHeader: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  children,
  ...props
}) => (
  <div
    className={cn(
      'px-2.5 py-1.5 text-[11px] font-mono font-semibold uppercase tracking-wider text-foreground-subtle border-b border-border-subtle mb-1',
      className
    )}
    {...props}
  >
    {children}
  </div>
);

export const DropdownDivider: React.FC<React.HTMLAttributes<HTMLDivElement>> = ({
  className,
  ...props
}) => <div className={cn('my-1 border-t border-border-subtle', className)} {...props} />;
