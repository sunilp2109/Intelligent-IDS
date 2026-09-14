import { useCallback, useEffect, useRef, useState } from "react";

export function useApi(loader, dependencyKey = "") {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const reload = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const result = await loaderRef.current();
      setData(result);
    } catch (err) {
      setData(null);
      setError(err instanceof Error ? err.message : "Unable to load security data.");
    } finally {
      setLoading(false);
    }
  }, [dependencyKey]);

  useEffect(() => {
    reload();
  }, [reload]);

  return { data, error, loading, reload };
}
