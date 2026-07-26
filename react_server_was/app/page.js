import { testAction } from './actions';

export default function Page() {
  return (
    <main>
      <h1>React Isolated Lab</h1>

      <form action={testAction}>
        <input name="message" defaultValue="hello" />
        <button type="submit">Call Server Action</button>
      </form>
    </main>
  );
}