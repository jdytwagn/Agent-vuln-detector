import { useEffect, useRef } from "react";

const CARD_SELECTOR = ".console-card, .card-elevation, .rule-card";
const COLORS = ["#0b6e66", "#e07a2f", "#5b4b8a", "#f4fbff"];

type Particle = {
  x: number;
  y: number;
  vx: number;
  vy: number;
  life: number;
  max: number;
  radius: number;
  color: string;
};

export function ParticleField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const context = canvas.getContext("2d");
    if (!context) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;

    const particles: Particle[] = [];
    let hover: HTMLElement | null = null;
    let frame = 0;
    let running = false;
    let lastSpawn = 0;
    let pointerX = 0;
    let pointerY = 0;
    const ratio = () => window.devicePixelRatio || 1;

    const resize = () => {
      const scale = ratio();
      canvas.width = Math.floor(window.innerWidth * scale);
      canvas.height = Math.floor(window.innerHeight * scale);
      canvas.style.width = `${window.innerWidth}px`;
      canvas.style.height = `${window.innerHeight}px`;
    };

    const spawn = (x: number, y: number) => {
      if (particles.length > 70) particles.splice(0, particles.length - 70);
      for (let index = 0; index < 3; index += 1) {
        const angle = Math.random() * Math.PI * 2;
        const speed = 0.35 + Math.random() * 1.15;
        particles.push({
          x,
          y,
          vx: Math.cos(angle) * speed,
          vy: Math.sin(angle) * speed - 0.45,
          life: 70 + Math.random() * 40,
          max: 110,
          radius: 2.2 + Math.random() * 2.6,
          color: COLORS[Math.floor(Math.random() * COLORS.length)]
        });
      }
    };

    const draw = () => {
      const scale = ratio();
      context.clearRect(0, 0, canvas.width, canvas.height);
      const card = hover?.isConnected ? hover : null;
      if (!card) {
        particles.splice(0, particles.length);
        running = false;
        return;
      }
      const rect = card.getBoundingClientRect();
      context.save();
      context.beginPath();
      context.rect(rect.left * scale, rect.top * scale, rect.width * scale, rect.height * scale);
      context.clip();
      for (let index = particles.length - 1; index >= 0; index -= 1) {
        const particle = particles[index];
        particle.x += particle.vx;
        particle.y += particle.vy;
        particle.life -= 1;
        if (particle.life <= 0) {
          particles.splice(index, 1);
          continue;
        }
        const alpha = Math.max(particle.life / particle.max, 0);
        context.globalAlpha = alpha;
        context.fillStyle = particle.color;
        context.shadowColor = particle.color;
        context.shadowBlur = 8 * scale;
        context.beginPath();
        context.arc(particle.x * scale, particle.y * scale, particle.radius * scale, 0, Math.PI * 2);
        context.fill();
        context.shadowBlur = 0;
      }
      context.globalAlpha = 0.35;
      context.strokeStyle = "#0e7c73";
      context.lineWidth = scale;
      for (let left = 0; left < particles.length; left += 1) {
        for (let right = left + 1; right < particles.length; right += 1) {
          const a = particles[left];
          const b = particles[right];
          const distance = Math.hypot(a.x - b.x, a.y - b.y);
          if (distance > 42) continue;
          context.globalAlpha = (1 - distance / 42) * 0.28;
          context.beginPath();
          context.moveTo(a.x * scale, a.y * scale);
          context.lineTo(b.x * scale, b.y * scale);
          context.stroke();
        }
      }
      context.restore();
      if (hover?.isConnected) {
        const now = performance.now();
        if (now - lastSpawn > 70) {
          lastSpawn = now;
          spawn(pointerX, pointerY);
        }
      }
      if (particles.length || hover) {
        frame = window.requestAnimationFrame(draw);
      } else {
        running = false;
      }
    };

    const ensure = () => {
      if (!running) {
        running = true;
        frame = window.requestAnimationFrame(draw);
      }
    };

    const onMove = (event: PointerEvent) => {
      const target = event.target instanceof Element ? event.target.closest(CARD_SELECTOR) : null;
      hover = target instanceof HTMLElement ? target : null;
      pointerX = event.clientX;
      pointerY = event.clientY;
      if (!hover) return;
      spawn(pointerX, pointerY);
      ensure();
    };

    const onOut = (event: PointerEvent) => {
      if (!hover) return;
      const next = event.relatedTarget;
      if (next instanceof Node && hover.contains(next)) return;
      hover = null;
    };

    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerout", onOut);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerout", onOut);
    };
  }, []);

  return <canvas ref={canvasRef} className="pointer-events-none fixed inset-0 z-20" aria-hidden="true" />;
}
