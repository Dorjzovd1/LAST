import { createContext, useContext, useEffect, useRef, useState } from "react";
import type { ReactNode } from "react";
import { connectEvents } from "../api/client";
import type { RealtimeEvent } from "../api/types";

interface EventsContextValue {
  lastEvent: RealtimeEvent | null;
  connected: boolean;
  subscribe: (cb: (ev: RealtimeEvent) => void) => () => void;
}

const EventsContext = createContext<EventsContextValue>({
  lastEvent: null,
  connected: false,
  subscribe: () => () => {},
});

export function EventsProvider({ children }: { children: ReactNode }) {
  const [lastEvent, setLastEvent] = useState<RealtimeEvent | null>(null);
  const [connected, setConnected] = useState(false);
  const subscribers = useRef<Set<(ev: RealtimeEvent) => void>>(new Set());

  useEffect(() => {
    let ws: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout>;

    const open = () => {
      ws = connectEvents((ev) => {
        setLastEvent(ev);
        subscribers.current.forEach((cb) => cb(ev));
      });
      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        retry = setTimeout(open, 3000);
      };
    };
    open();
    return () => {
      clearTimeout(retry);
      ws?.close();
    };
  }, []);

  const subscribe = (cb: (ev: RealtimeEvent) => void) => {
    subscribers.current.add(cb);
    return () => subscribers.current.delete(cb);
  };

  return (
    <EventsContext.Provider value={{ lastEvent, connected, subscribe }}>
      {children}
    </EventsContext.Provider>
  );
}

export const useEvents = () => useContext(EventsContext);
