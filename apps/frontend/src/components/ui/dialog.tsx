import * as Dialog from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
export function Modal({
  title,
  children,
  onClose,
  closeDisabled = false,
}: {
  title: string;
  children: React.ReactNode;
  onClose: () => void;
  closeDisabled?: boolean;
}) {
  return (
    <Dialog.Root open onOpenChange={(open) => !open && !closeDisabled && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="modal-overlay" />
        <Dialog.Content className="modal">
          <div className="modal-head">
            <Dialog.Title>{title}</Dialog.Title>
            <Dialog.Close
              className="icon-button"
              aria-label="Close dialog"
              disabled={closeDisabled}
            >
              <X size={20} />
            </Dialog.Close>
          </div>
          <Dialog.Description className="sr-only">
            Review the operation and its exact execution context.
          </Dialog.Description>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
