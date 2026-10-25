import { useEffect, useRef } from "react";

const RINGS = 3;
const PER_RING = 84;
const BLUE = [91, 156, 255] as const;
const PALE = [186, 214, 255] as const;

type Point = {
  ring: number;
  index: number;
  ox: number;
  oy: number;
  phase: number;
  seed: number;
};

function hash(value: number) {
  const mixed = Math.sin(value * 127.1) * 43758.5453;
  return mixed - Math.floor(mixed);
}

function mix(from: number, to: number, amount: number) {
  return from + (to - from) * amount;
}

export function CursorRingField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const context = canvas.getContext("2d", { alpha: true });
    if (!context) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const points: Point[] = [];
    for (let ring = 0; ring < RINGS; ring += 1) {
      for (let index = 0; index < PER_RING; index += 1) {
        const id = ring * PER_RING + index;
        points.push({
          ring,
          index,
          ox: 0,
          oy: 0,
          phase: hash(id + 3) * Math.PI * 2,
          seed: hash(id + 9)
        });
      }
    }

    let frame = 0;
    let pointer: { x: number; y: number } | null = null;
    let presence = 0;
    const ratio = () => Math.min(window.devicePixelRatio || 1, 2);

    const resize = () => {
      const scale = ratio();
      canvas.width = Math.floor(window.innerWidth * scale);
      canvas.height = Math.floor(window.innerHeight * scale);
      canvas.style.width = `${window.innerWidth}px`;
      canvas.style.height = `${window.innerHeight}px`;
    };

    const draw = (time: number) => {
      const scale = ratio();
      const width = canvas.width / scale;
      const height = canvas.height / scale;
      context.setTransform(scale, 0, 0, scale, 0, 0);
      context.clearRect(0, 0, width, height);
      presence += ((pointer ? 1 : 0) - presence) * 0.08;
      if (presence > 0.02 && pointer) {
        const baseRadius = 92;
        for (const point of points) {
          const spread = (point.ring - 1) * 11;
          const angle = (point.index / PER_RING) * Math.PI * 2 + point.phase * 0.15;
          const wobble = Math.sin(angle * 3 + time * 0.0012 + point.phase) * 4;
          const localRadius = baseRadius + spread + wobble;
          const outwardX = Math.cos(angle);
          const outwardY = Math.sin(angle);
          const homeX = pointer.x + outwardX * localRadius;
          const homeY = pointer.y + outwardY * localRadius;
          const crest = 1 - Math.abs(spread) / 16;
          if (!reduced) {
            const desired = 7 * (0.45 + crest * 0.55);
            point.ox = point.ox * 0.8 + outwardX * desired * 0.2;
            point.oy = point.oy * 0.8 + outwardY * desired * 0.2;
          }
          const x = homeX + point.ox;
          const y = homeY + point.oy;
          const facing = angle + (point.seed - 0.5) * 0.5;
          const length = 3.4 + point.seed * 2.2;
          const thickness = 1.05 + point.seed * 0.35;
          const alpha = presence * (0.42 + crest * 0.45);
          const red = mix(BLUE[0], PALE[0], crest);
          const green = mix(BLUE[1], PALE[1], crest);
          const blue = mix(BLUE[2], PALE[2], crest);
          context.save();
          context.translate(x, y);
          context.rotate(facing);
          context.fillStyle = `rgba(${red}, ${green}, ${blue}, ${alpha})`;
          context.beginPath();
          context.roundRect(-length / 2, -thickness / 2, length, thickness, thickness / 2);
          context.fill();
          context.restore();
        }
      }
      frame = window.requestAnimationFrame(draw);
    };

    const onMove = (event: PointerEvent) => {
      pointer = { x: event.clientX, y: event.clientY };
    };
    const onLeave = () => {
      pointer = null;
    };

    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onMove);
    document.addEventListener("pointerleave", onLeave);
    frame = window.requestAnimationFrame(draw);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerleave", onLeave);
    };
  }, []);

  return <canvas ref={canvasRef} className="pointer-events-none fixed inset-0" style={{ zIndex: 48 }} aria-hidden="true" />;
}
