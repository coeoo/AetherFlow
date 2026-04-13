type Props = {
  content: string | null;
  loading: boolean;
  errorMessage: string | null;
};

function getLineClassName(line: string) {
  if (line.startsWith("+")) {
    return "diff-line diff-line-add";
  }
  if (line.startsWith("-")) {
    return "diff-line diff-line-remove";
  }
  return "diff-line diff-line-context";
}

export function CVEDiffViewer({ content, loading, errorMessage }: Props) {
  const lines = content?.split("\n") ?? [];

  return (
    <section className="cve-panel cve-diff-panel">
      <div className="cve-panel-header">
        <p className="card-label">Diff Viewer</p>
        <h3>补丁内容</h3>
      </div>
      {loading ? <p className="card-copy">正在加载 Diff…</p> : null}
      {!loading && errorMessage ? <p className="cve-error-copy">{errorMessage}</p> : null}
      {!loading && !errorMessage && !content ? <p className="card-copy">选择一个已下载 patch 后即可查看内容。</p> : null}
      {!loading && !errorMessage && content ? (
        <pre className="cve-diff-viewer" aria-label="Diff 内容">
          {lines.map((line, index) => (
            <div key={`${line}-${index}`} className={getLineClassName(line)}>
              {line || " "}
            </div>
          ))}
        </pre>
      ) : null}
    </section>
  );
}
