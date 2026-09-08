import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className="py-16 text-center">
      <p className="text-sm uppercase tracking-widest text-ink-faint">404</p>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight text-ink">
        Page not found
      </h1>
      <Link to="/dashboard" className="mt-4 inline-block text-sm text-brand hover:underline">
        Go to dashboard
      </Link>
    </div>
  );
}
