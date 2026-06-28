import { Aurora } from "@/components/Aurora";
import { Nav } from "@/components/Nav";
import { Hero } from "@/sections/Hero";
import { Gap } from "@/sections/Gap";
import { Pipeline } from "@/sections/Pipeline";
import { AuditorConsole } from "@/sections/AuditorConsole";
import { OnChain } from "@/sections/OnChain";
import { Footer } from "@/sections/Footer";

export default function Home() {
  return (
    <main className="relative overflow-x-clip">
      <Aurora />
      <Nav />
      <Hero />
      <Gap />
      <Pipeline />
      <AuditorConsole />
      <OnChain />
      <Footer />
    </main>
  );
}
