import { useCallback, useEffect, useRef, useState } from "react";
import { isTypingTarget } from "../dom";

// The Konami code, keyboard-event-key form ("b"/"a" rather than "B"/"A" — see
// the lowercase compare below).
const SEQUENCE = ["ArrowUp", "ArrowUp", "ArrowDown", "ArrowDown", "ArrowLeft", "ArrowRight", "ArrowLeft", "ArrowRight", "b", "a"];

// The fanfare is a short, wholly original 8-bit-style square-wave riff (C5
// D5 E5 G5 E5 C6 G5 C6) — not a reproduction of any existing song — bundled
// as ui/public/konami.mp3 (rendered from the same notes this component used
// to synthesize live via the Web Audio API).
const FANFARE_SRC = "/konami.mp3";

// KonamiShark listens for the Konami code (↑↑↓↓←→←→BA) anywhere in the app
// (except while typing in a field) and, on match, sends a shark swimming
// across the screen with a little fanfare — Escape cuts both short. Pure
// easter egg, no functional side effects.
export function KonamiShark() {
  const posRef = useRef(0);
  const [active, setActive] = useState(false);
  // Mirrors `active` for the keydown handler below, which is attached once
  // (empty dep effect) and so only ever sees the `active` value from that
  // first render unless it reads through a ref instead.
  const activeRef = useRef(false);
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const hideTimerRef = useRef<number | null>(null);

  const stop = useCallback(() => {
    if (hideTimerRef.current !== null) {
      window.clearTimeout(hideTimerRef.current);
      hideTimerRef.current = null;
    }
    if (audioRef.current) {
      audioRef.current.pause();
      audioRef.current.currentTime = 0;
    }
    activeRef.current = false;
    setActive(false);
  }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && activeRef.current) {
        stop();
        return;
      }
      if (isTypingTarget(e.target)) return;
      const got = e.key.length === 1 ? e.key.toLowerCase() : e.key;
      const want = SEQUENCE[posRef.current];
      if (got === want) {
        posRef.current++;
        if (posRef.current === SEQUENCE.length) {
          posRef.current = 0;
          if (!audioRef.current) audioRef.current = new Audio(FANFARE_SRC);
          audioRef.current.currentTime = 0;
          audioRef.current.play().catch(() => {}); // e.g. no user gesture yet — silently skip, shark still swims
          activeRef.current = true;
          setActive(true);
          hideTimerRef.current = window.setTimeout(stop, 3000);
        }
      } else {
        // Restart the match, but allow the failed key to itself be a fresh
        // start (e.g. the ArrowUp of the *next* attempt right after a miss).
        posRef.current = got === SEQUENCE[0] ? 1 : 0;
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [stop]);

  if (!active) return null;
  return (
    <div className="konami-shark" aria-hidden="true">
      <span className="konami-shark-dance">🦈</span>
    </div>
  );
}
