import * as openpgp from "openpgp";
import { Readable } from "stream";
import fs from 'fs';
import { DecryptOptions, GenerateKeyOptions } from "openpgp";

async function encryptStream(
  readableStream: Readable,
  publicKeyArmored: string
): Promise<Readable> {
  const publicKey = await openpgp.readKey({ armoredKey: publicKeyArmored });
  const encryptedReadStream = await openpgp.encrypt({
    message: await openpgp.createMessage({ binary: readableStream }),
    encryptionKeys: publicKey,
  });
  return encryptedReadStream as Readable;
}

async function decryptStream(
  readableStream: Readable,
  privateKeyArmored: string
): Promise<Readable> {
  const privateKey = await openpgp.readPrivateKey({
    armoredKey: privateKeyArmored,
  });

  const message = await openpgp.readMessage({
    armoredMessage: readableStream,
  });

  const options: DecryptOptions = {
    message,
    decryptionKeys: privateKey,
    format: "binary",
  };

  const decrypted = await openpgp.decrypt(options);
  const decryptedReadStream = decrypted.data as Readable;
  return decryptedReadStream;
}

async function createFileFromReadStream(readStream: Readable, outputFileName: string) {
  await new Promise((resolve, reject) => {
    readStream
      .pipe(
        fs.createWriteStream(outputFileName)
        .on('finish', () => {
          resolve(null);
        })
        .on('error', (error) => {
          console.error(error);
          reject(error);
        })
      )
  });
}

async function decryptFromFileStreamDoesNotWork() {
  try {
    const options: GenerateKeyOptions & { format?: 'armored' } = { userIDs: {} };
    const { privateKey, publicKey } = await openpgp.generateKey(options);
  
    const readStream = fs.createReadStream('test/sample.txt');
    const encryptedReadStream = await encryptStream(readStream, publicKey);
  
    await createFileFromReadStream(encryptedReadStream, 'test/output.sample.encrypted');
  
    const readStream2 = fs.createReadStream('test/output.sample.encrypted');
    const decryptReadStream = await decryptStream(readStream2, privateKey);
  
    await createFileFromReadStream(decryptReadStream, 'test/output.sample.decrypted');
  
    console.log(`decryptFromFileStreamDoesNotWork() finished successfully`);
  } catch (error) {
    console.log(`decryptFromFileStreamDoesNotWork() failed`);
    console.error(error);
  }
  
}

async function decryptFromFileStreamDoesNotWork_solution() {
  try {
    const options: GenerateKeyOptions & { format?: 'armored' } = { userIDs: {} };
    const { privateKey, publicKey } = await openpgp.generateKey(options);
  
    const readStream = fs.createReadStream('test/sample.txt');
    const encryptedReadStream = await encryptStream(readStream, publicKey);
  
    await createFileFromReadStream(encryptedReadStream, 'test/output.sample.encrypted');
  
    // SOLUTION: set encoding utf8
    const readStream2 = fs.createReadStream('test/output.sample.encrypted', 'utf8');
    const decryptReadStream = await decryptStream(readStream2, privateKey);
  
    await createFileFromReadStream(decryptReadStream, 'test/output.sample.decrypted');
  
    console.log(`decryptFromFileStreamDoesNotWork() finished successfully`);
  } catch (error) {
    console.log(`decryptFromFileStreamDoesNotWork() failed`);
    console.error(error);
  }
  
}

async function decryptFromOwnOpenPgpStreamWorks() {
  try {
    const options: GenerateKeyOptions & { format?: 'armored' } = { userIDs: {} };
    const { privateKey, publicKey } = await openpgp.generateKey(options);

    const readStream = fs.createReadStream('test/sample.txt');
    const encryptedReadStream = await encryptStream(readStream, publicKey);
    const decryptReadStream = await decryptStream(encryptedReadStream, privateKey);

    await createFileFromReadStream(decryptReadStream, 'test/output.sample.decrypted');
    console.log(`decryptFromOwnOpenPgpStreamWorks() finished successfully`);
  } catch (error) {
    console.log(`decryptFromOwnOpenPgpStreamWorks() failed`);
    console.error(error);
  }
}

async function main() {
  await decryptFromOwnOpenPgpStreamWorks();
  await decryptFromFileStreamDoesNotWork_solution();
  await decryptFromFileStreamDoesNotWork();
}

main();