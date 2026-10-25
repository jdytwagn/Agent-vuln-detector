import { useEffect, useRef } from "react";

const BACKGROUND = "#04050A";
const COUNT = 520;
const CYAN = [46, 230, 200] as const;
const LIME = [214, 255, 74] as const;

type Point = {
  x: number;
  y: number;
  ox: number;
  oy: number;
  phase: number;
  seed: number;
};

function hash(value: number) {
  const mixed = Math.sin(value * 127.1) * 43758.5453;
  return mixed - Math.floor(mixed);
}

function smoothstep(edge0: number, edge1: number, value: number) {
  const span = edge1 - edge0 || 1;
  const t = Math.min(1, Math.max(0, (value - edge0) / span));
  return t * t * (3 - 2 * t);
}

function mix(from: number, to: number, amount: number) {
  return from + (to - from) * amount;
}

export function CursorRingField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const context = canvas.getContext("2d");
    if (!context) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    const points: Point[] = [];
    const columns = 26;
    const rows = Math.ceil(COUNT / columns);
    for (let index = 0; index < COUNT; index += 1) {
      const column = index % columns;
      const row = Math.floor(index / columns);
      points.push({
        x: (column + 0.5 + (hash(index + 1) - 0.5) * 0.92) / columns,
        y: (row + 0.5 + (hash(index + 17) - 0.5) * 0.92) / rows,
        ox: 0,
        oy: 0,
        phase: hash(index + 3) * Math.PI * 2,
        seed: hash(index + 9)
      });
    }

    let frame = 0;
    let pointer: { x: number; y: number } | null = null;
    const ratio = () => Math.min(window.devicePixelRatio || 1, 2);

    const resize = () => {
      const scale = ratio();
      canvas.width = Math.floor(window.innerWidth * scale);
      canvas.height = Math.floor(window.innerHeight * scale);
      canvas.style.width = `${window.innerWidth}px`;
      canvas.style.height = `${window.innerHeight}px`;
    };

    const ringCenter = (width: number, height: number, time: number) => {
      if (pointer) return pointer;
      const wanderX = 0.5 + 0.16 * Math.sin(time * 0.00017) + 0.07 * Math.sin(time * 0.00007);
      const wanderY = 0.46 + 0.14 * Math.cos(time * 0.00013) + 0.06 * Math.sin(time * 0.00005);
      return { x: wanderX * width, y: wanderY * height };
    };

    const draw = (time: number) => {
      const scale = ratio();
      const width = canvas.width / scale;
      const height = canvas.height / scale;
      context.setTransform(scale, 0, 0, scale, 0, 0);
      context.fillStyle = BACKGROUND;
      context.fillRect(0, 0, width, height);
      const ring = ringCenter(width, height, time);
      const radius = Math.min(width, height) * 0.28;
      const band = radius * (9 / 12);
      const push = 22;

      for (const point of points) {
        const homeX = point.x * width;
        const homeY = point.y * height;
        const depth = 0.82 + point.y * 0.36;
        const angleToRing = Math.atan2(homeY - ring.y, homeX - ring.x);
        const wobble = Math.sin(angleToRing * 3 + time * 0.0006 + point.phase) * 14;
        const localRadius = radius + wobble;
        const distance = Math.hypot(homeX - ring.x, homeY - ring.y);
        const enter = smoothstep(localRadius - band, localRadius - band * 0.45, distance);
        const crest = smoothstep(localRadius - band * 0.2, localRadius, distance);
        const leave = 1 - smoothstep(localRadius + band * 0.05, localRadius + band, distance);
        const influence = enter * leave;
        const hot = crest * leave;
        const desired = push * influence;
        if (!reduced) {
          point.ox = point.ox * 0.8 + Math.cos(angleToRing) * desired * 0.2;
          point.oy = point.oy * 0.8 + Math.sin(angleToRing) * desired * 0.2;
        }
        const x = homeX + point.ox;
        const y = homeY + point.oy;
        const facing = Math.atan2(ring.y - y, ring.x - x) + (point.seed - 0.5) * 0.9;
        const length = (10 + point.seed * 7) * depth * (1 + hot * 0.35);
        const thickness = (1.7 + point.seed * 1.1) * depth;
        const shimmer = 0.82 + 0.18 * Math.sin(time * 0.001 + point.phase);
        const alpha = (0.5 + influence * 0.5) * shimmer;
        const ambient = mix(0.55, 1, point.seed);
        const tint = Math.min(1, influence * 0.55 + hot);
        const red = mix(mix(12, CYAN[0], ambient), LIME[0], tint);
        const green = mix(mix(150, CYAN[1], ambient), LIME[1], tint);
        const blue = mix(mix(140, CYAN[2], ambient), LIME[2], tint);

        context.save();
        context.translate(x, y);
        context.rotate(facing);
        context.fillStyle = `rgba(${red}, ${green}, ${blue}, ${alpha * 0.28})`;
        context.beginPath();
        context.roundRect(-length * 0.72, -thickness * 1.7, length * 1.44, thickness * 3.4, thickness * 1.7);
        context.fill();
        context.fillStyle = `rgba(${red}, ${green}, ${blue}, ${alpha})`;
        context.beginPath();
        context.roundRect(-length / 2, -thickness / 2, length, thickness, thickness / 2);
        context.fill();
        context.restore();
      }

      if (!reduced) frame = window.requestAnimationFrame(draw);
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
    window.addEventListener("pointerleave", onLeave);
    frame = window.requestAnimationFrame(draw);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerleave", onLeave);
    };
  }, []);

  return <canvas ref={canvasRef} className="pointer-events-none fixed inset-0 z-0" aria-hidden="true" />;
}
