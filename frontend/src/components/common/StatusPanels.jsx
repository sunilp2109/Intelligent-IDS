export function LoadingState({ message = "Loading security data..." }) {
  return (
    <div className="panel px-4 py-8 text-center text-sm text-soc-muted" role="status">
      {message}
    </div>
  );
}

export function EmptyState({ message = "No security events recorded." }) {
  return (
    <div className="panel px-4 py-8 text-center text-sm text-soc-muted" role="status">
      {message}
    </div>
  );
}

export function ErrorState({ message = "Unable to load security data." }) {
  return (
    <div className="rounded border border-red-800 bg-red-950/40 px-4 py-8 text-center text-sm text-red-200" role="alert">
      {message}
    </div>
  );
}
