import os

import pandas as pd

from preprocess import clean_text


def main() -> None:
    try:
        import tensorflow as tf  # type: ignore
    except Exception as e:  # pragma: no cover
        raise SystemExit(
            "TensorFlow is not installed. Install it first (see requirements-tf.txt)."
        ) from e

    data = pd.read_csv("messages.csv", encoding="utf-8").dropna(subset=["text", "label"]).copy()
    data["text_clean"] = data["text"].astype(str).map(clean_text)
    data = data[data["text_clean"].str.len() > 0]

    texts = data["text_clean"].astype(str).tolist()
    labels = data["label"].astype(int).tolist()

    # Very small datasets overfit easily; keep the model tiny.
    text_vec = tf.keras.layers.TextVectorization(
        max_tokens=20000,
        ngrams=2,
        output_mode="tf-idf",
    )
    text_vec.adapt(texts)

    model = tf.keras.Sequential(
        [
            text_vec,
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dropout(0.25),
            tf.keras.layers.Dense(1, activation="sigmoid"),
        ]
    )

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=1e-3),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )

    callbacks = [
        tf.keras.callbacks.EarlyStopping(monitor="loss", patience=3, restore_best_weights=True)
    ]

    model.fit(texts, labels, epochs=25, batch_size=8, verbose=1, callbacks=callbacks)

    out_dir = os.environ.get("SAFESCAN_TF_MODEL_DIR", "tf_model")
    model.save(out_dir)
    print(f"Saved TensorFlow model to: {out_dir}")


if __name__ == "__main__":
    main()

