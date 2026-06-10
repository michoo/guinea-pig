// FALSE POSITIVE — not a secret.
// Resembles: generic high-entropy / base64 secret rules (long opaque strings).
// Why benign: these are Tailwind CSS utility class lists. They are high-entropy to a
// regex but are just styling tokens with no security meaning.

export function Card({ title, children }) {
  return (
    <div className="relative isolate overflow-hidden rounded-2xl bg-gray-900/80 px-6 py-8 shadow-2xl ring-1 ring-white/10 backdrop-blur-md sm:px-10 lg:px-12">
      <h2 className="text-lg font-semibold leading-7 tracking-tight text-indigo-300 group-hover:text-indigo-200">
        {title}
      </h2>
      <div className="mt-4 grid grid-cols-1 gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3 [&>*]:min-w-0">
        {children}
      </div>
    </div>
  );
}
