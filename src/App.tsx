import "./styles.css";
import logo from "../logo.svg";

export function App() {
  return (
    <main className="app-shell">
      <img className="brand-mark" src={logo} alt="" />
      <h1>Good Morning Breach</h1>
      <p>Application scaffold</p>
    </main>
  );
}
