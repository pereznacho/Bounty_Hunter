import React, { useEffect, useState } from "react";

const isDomain = (target) => {
  const domainRegex = /^(\*\.?|)([a-zA-Z0-9.-]+\.[a-z]{2,})$/;
  return domainRegex.test(target);
};

const isURL = (target) => {
  const urlRegex = /^(https?:\/\/|www\.)[^\s/$.?#].[^\s]*$/i;
  return urlRegex.test(target);
};

export default function HackerOnePrograms() {
  const [programs, setPrograms] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch("/hackerone/import")
      .then((res) => res.json())
      .then((data) => {
        setPrograms(data.programs);
        setLoading(false);
      })
      .catch((err) => {
        console.error(err);
        setError("Error al obtener los programas.");
        setLoading(false);
      });
  }, []);

  if (loading) return <div className="text-white">Cargando programas...</div>;
  if (error) return <div className="text-red-400">{error}</div>;

  return (
    <div className="p-6 text-white">
      <h1 className="text-2xl font-bold mb-6 text-teal-300">Programas de HackerOne</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {programs.map((program, idx) => {
          const domains = [];
          const urls = [];

          program.targets?.forEach((target) => {
            const asset = target.asset_identifier?.trim();
            if (isDomain(asset)) domains.push(asset);
            else if (isURL(asset)) urls.push(asset);
          });

          return (
            <div key={idx} className="bg-zinc-800 rounded-lg p-5 shadow-md border border-zinc-700">
              <div className="mb-3">
                <h2 className="text-xl font-semibold text-cyan-300">{program.name}</h2>
                <a
                  href={program.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-sm text-teal-400 hover:underline"
                >
                  {program.url}
                </a>
                <p className="text-sm mt-1">Handle: <span className="text-amber-300">{program.handle}</span></p>
                <p className="text-sm">
                  Máx. recompensa:{" "}
                  <span className="text-green-400">
                    {program.max_bounty ? `$${program.max_bounty}` : "N/A"}
                  </span>
                </p>
              </div>

              {domains.length > 0 && (
                <div className="mb-2">
                  <h3 className="text-md font-medium text-pink-400">Dominios</h3>
                  <ul className="pl-2">
                    {domains.map((domain, i) => (
                      <li key={i} className="flex items-center gap-2 mt-1">
                        <input type="checkbox" id={`d-${idx}-${i}`} className="accent-pink-400" />
                        <label htmlFor={`d-${idx}-${i}`} className="text-sm">{domain}</label>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {urls.length > 0 && (
                <div>
                  <h3 className="text-md font-medium text-purple-400">URLs</h3>
                  <ul className="pl-2">
                    {urls.map((url, i) => (
                      <li key={i} className="flex items-center gap-2 mt-1">
                        <input type="checkbox" id={`u-${idx}-${i}`} className="accent-purple-400" />
                        <label htmlFor={`u-${idx}-${i}`} className="text-sm break-all">{url}</label>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}