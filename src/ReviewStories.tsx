import { useCallback, useEffect, useState } from "react";

export type ReviewStory = {
  id: number;
  title: string;
  url: string;
  excerpt: string;
  sources: string[];
  publishedAt: string;
  approvedAt: string | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function parseReviewStories(value: unknown): ReviewStory[] | null {
  if (!isRecord(value) || !Array.isArray(value.stories)) return null;
  const out: ReviewStory[] = [];
  for (const item of value.stories) {
    if (!isRecord(item) || typeof item.id !== "number" || typeof item.title !== "string" || typeof item.url !== "string" ||
        typeof item.excerpt !== "string" || typeof item.publishedAt !== "string" ||
        !Array.isArray(item.sources) || !item.sources.every((s) => typeof s === "string") ||
        (item.approvedAt !== null && typeof item.approvedAt !== "string")) return null;
    out.push({
      id: item.id, title: item.title, url: item.url, excerpt: item.excerpt,
      sources: item.sources as string[], publishedAt: item.publishedAt, approvedAt: item.approvedAt,
    });
  }
  return out;
}

function safeLink(value: string): URL | null {
  try {
    const url = new URL(value);
    return url.protocol === "https:" || url.protocol === "http:" ? url : null;
  } catch {
    return null;
  }
}

// Admin review of excerpts from conditional-license sources (FR-8.8). An excerpt
// is shown to readers only after the story is approved here.
export function ReviewStories() {
  const [stories, setStories] = useState<ReviewStory[] | null>(null);
  const [message, setMessage] = useState("");
  const [busyID, setBusyID] = useState<number | null>(null);

  const load = useCallback(async () => {
    const response = await fetch("/api/admin/review-stories", { credentials: "same-origin" });
    if (!response.ok) throw new Error("Could not load stories for review.");
    const parsed = parseReviewStories(await response.json());
    if (!parsed) throw new Error("The server returned invalid review data.");
    setStories(parsed);
  }, []);

  useEffect(() => {
    load().catch((error: unknown) => setMessage(error instanceof Error ? error.message : "Could not load stories for review."));
  }, [load]);

  async function decide(story: ReviewStory, approved: boolean) {
    setBusyID(story.id);
    setMessage("");
    try {
      const response = await fetch(`/api/admin/review-stories/${story.id}`, {
        method: "PUT",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", "X-GMB-CSRF": "1" },
        body: JSON.stringify({ approved }),
      });
      if (!response.ok) throw new Error("Could not save the review decision.");
      await load();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Could not save the review decision.");
    } finally {
      setBusyID(null);
    }
  }

  const pending = stories?.filter((story) => story.approvedAt === null).length ?? 0;
  return (
    <section className="admin-panel" aria-labelledby="review-heading">
      <div className="dashboard-heading">
        <div>
          <h2 id="review-heading">Excerpt review</h2>
          <p className="muted">Stories from conditional-license sources show their excerpt only after you approve them. Until then readers see the headline and link.</p>
        </div>
      </div>
      {message && <p className="form-error" role="alert">Error: {message}</p>}
      {stories === null ? <p className="muted">Loading stories for review…</p> : stories.length === 0 ? (
        <p className="muted">No stories are waiting for review.</p>
      ) : (
        <>
          <p className="muted">{pending} waiting for review.</p>
          <ul className="review-list">
            {stories.map((story) => {
              const link = safeLink(story.url);
              return (
                <li key={story.id} className="review-item">
                  <h3 className="review-title">
                    {link ? <a href={link.href} target="_blank" rel="noopener noreferrer">{story.title}</a> : story.title}
                    {link && <span className="story-domain"> {link.hostname}</span>}
                  </h3>
                  <p className="story-meta">Sources: {story.sources.join(", ")}</p>
                  <p className="review-excerpt">{story.excerpt}</p>
                  <div className="admin-actions">
                    {story.approvedAt === null ? (
                      <button type="button" className="table-button" disabled={busyID !== null}
                        onClick={() => void decide(story, true)}>{busyID === story.id ? "Saving…" : "Approve excerpt"}</button>
                    ) : (
                      <>
                        <span className="muted">Approved</span>
                        <button type="button" className="table-button" disabled={busyID !== null}
                          onClick={() => void decide(story, false)}>{busyID === story.id ? "Saving…" : "Revoke approval"}</button>
                      </>
                    )}
                  </div>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </section>
  );
}
