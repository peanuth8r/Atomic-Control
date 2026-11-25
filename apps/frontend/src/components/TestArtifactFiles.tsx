import { useEffect, useState } from 'react';
import type { AtomicTest } from '../types';
import { api } from '../services/api';

export type SupportingFiles = {
  asset_paths: string[];
  files: { path: string; content_base64: string }[];
};
export default function TestArtifactFiles({
  test,
  onChange,
  disabled = false,
}: {
  test: AtomicTest;
  disabled?: boolean;
  onChange: (value: SupportingFiles) => void;
}) {
  const [paths, setPaths] = useState('');
  const [files, setFiles] = useState<Record<string, string>>({});
  const [loaded, setLoaded] = useState(false);
  const [submittedFiles, setSubmittedFiles] = useState<
    { path: string; size: number; sha256: string }[]
  >([]);
  const [error, setError] = useState('');
  const declared = [
    ...new Set(
      paths
        .split('\n')
        .map((p) => p.trim())
        .filter(Boolean),
    ),
  ];
  useEffect(() => {
    let active = true;
    api<{
      file_plan?: AtomicTest['file_plan'];
      artifact: AtomicTest['artifact'];
      suggested_assets: string[];
      submitted_files?: { path: string; size: number; sha256: string }[];
      error: string;
    }>(`/tests/${test.guid}/artifact`)
      .then((data) => {
        if (!active) return;
        const manifest = data.file_plan?.manifest || data.artifact?.manifest;
        setPaths(
          (manifest
            ? manifest.files
                .map((f) => f.path)
                .filter((p) => p !== `atomics/${test.technique}/${test.technique}.yaml`)
            : data.suggested_assets
          ).join('\n'),
        );
        setError(data.error);
        setSubmittedFiles(data.submitted_files || []);
        setLoaded(true);
      })
      .catch((e) => active && setError((e as Error).message));
    return () => {
      active = false;
    };
  }, [test.guid, test.content_sha256, test.revision]);
  useEffect(() => {
    if (!loaded) return;
    onChange({
      asset_paths: [
        ...new Set(
          paths
            .split('\n')
            .map((p) => p.trim())
            .filter(Boolean),
        ),
      ],
      files: Object.entries(files)
        .filter(([path]) =>
          paths
            .split('\n')
            .map((p) => p.trim())
            .includes(path),
        )
        .map(([path, content_base64]) => ({ path, content_base64 })),
    });
  }, [paths, files, loaded, onChange]);
  const upload = (path: string, file?: File) => {
    if (!file) return;
    if (file.size > 16 * 1024 * 1024) {
      setError('Each supporting file must be 16 MiB or smaller.');
      return;
    }
    const reader = new FileReader();
    reader.onload = () =>
      setFiles((current) => ({ ...current, [path]: String(reader.result).split(',')[1] }));
    reader.onerror = () => setError('Could not read the supporting file.');
    reader.readAsDataURL(file);
  };
  const manifest = test.file_plan?.manifest || test.artifact?.manifest;
  return (
    <section className="profile-detail" aria-label="Supporting test files">
      <h3>Supporting test files</h3>
      <p>
        Approve this definition and its supporting files together. Run or Queue automatically
        packages the approved files before execution; no separate preparation is needed.
      </p>
      {manifest && (
        <ul>
          {manifest.files.map((file) => (
            <li key={file.path}>
              <code>{file.path}</code> · {file.size.toLocaleString()} bytes{' '}
              <small>
                SHA-256: <code>{file.sha256}</code>
              </small>
            </li>
          ))}
        </ul>
      )}
      {!manifest && submittedFiles.length > 0 && (
        <>
          <p>Submitted supporting files await your review and will be included during approval.</p>
          <ul>
            {submittedFiles.map((file) => (
              <li key={file.path}>
                <code>{file.path}</code> · {file.size.toLocaleString()} bytes{' '}
                <small>
                  SHA-256: <code>{file.sha256}</code>
                </small>
              </li>
            ))}
          </ul>
        </>
      )}
      <details>
        <summary>Supporting file paths and custom uploads</summary>
        <label htmlFor="artifact-paths">Supporting files (one repository path per line)</label>
        <textarea
          id="artifact-paths"
          rows={4}
          disabled={disabled}
          value={paths}
          placeholder="atomics/Txxxx/src/example.sh"
          onChange={(e) => setPaths(e.target.value)}
        />
        <p className="field-help">
          {test.catalog_source === 'github'
            ? 'Files are verified against this exact official source commit during approval.'
            : submittedFiles.length
              ? 'Submitted custom files are retained for approval. Upload a file only to replace its submitted content.'
              : 'Attach each declared custom file before approval. Previously retained files do not need another upload.'}{' '}
          The selected test YAML is included automatically. Prerequisite software is provisioned
          separately.
        </p>
        {test.catalog_source !== 'github' &&
          declared.map((path) => (
            <label key={path}>
              {path}
              <input
                type="file"
                disabled={disabled}
                aria-label={`Upload ${path}`}
                onChange={(e) => upload(path, e.target.files?.[0])}
              />
            </label>
          ))}
      </details>
      {test.file_plan && (
        <p>Supporting files approved. Packaging happens automatically when a run needs them.</p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
