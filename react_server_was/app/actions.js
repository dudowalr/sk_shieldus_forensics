'use server';

export async function testAction(formData) {
  const value = formData.get('message');
  console.log('Server Action received:', value);
}