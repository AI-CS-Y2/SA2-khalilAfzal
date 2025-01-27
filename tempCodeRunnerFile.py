import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, accuracy_score, roc_curve, auc
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
import matplotlib.pyplot as plt

# The Data set Is loaded.
data = pd.read_csv('heart_failure_clinical_records_dataset.csv')

# Preprocesing the data.
def preprocess_data(data):
    X = data.drop(columns=['DEATH_EVENT'])
    y = data['DEATH_EVENT']
    X = (X - X.min()) / (X.max() - X.min())
    return X.values, y.values

X, y = preprocess_data(data)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Here comes the Logistic Regression.
logistic_model = LogisticRegression()
logistic_params = {'C': [0.01, 0.1, 1, 10, 100], 'penalty': ['l1', 'l2'], 'solver': ['liblinear']}
grid_logistic = GridSearchCV(logistic_model, logistic_params, cv=5, scoring='accuracy')
grid_logistic.fit(X_train, y_train)
best_logistic = grid_logistic.best_estimator_
y_pred_logistic = best_logistic.predict(X_test)

logistic_accuracy = accuracy_score(y_test, y_pred_logistic)
print("Logistic Regression Model Accuracy:", logistic_accuracy)
print("Logistic Regression Classification Report:")
print(classification_report(y_test, y_pred_logistic))

#The KNN is used.
knn_model = KNeighborsClassifier()
knn_params = {'n_neighbors': [3, 5, 7, 9], 'weights': ['uniform', 'distance'], 'metric': ['euclidean', 'manhattan']}
grid_knn = GridSearchCV(knn_model, knn_params, cv=5, scoring='accuracy')
grid_knn.fit(X_train, y_train)
best_knn = grid_knn.best_estimator_
y_pred_knn = best_knn.predict(X_test)

knn_accuracy = accuracy_score(y_test, y_pred_knn)
print("K-Nearest Neighbors (KNN) Model Accuracy:", knn_accuracy)
print("K-Nearest Neighbors (KNN) Classification Report:")
print(classification_report(y_test, y_pred_knn))

# The Decesion tree is used.
decision_tree_model = DecisionTreeClassifier(random_state=42)
decision_tree_params = {
    'criterion': ['gini', 'entropy'],
    'max_depth': [3, 5, 10, None],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf': [1, 2, 4]
}
grid_tree = GridSearchCV(decision_tree_model, decision_tree_params, cv=5, scoring='accuracy')
grid_tree.fit(X_train, y_train)
best_tree = grid_tree.best_estimator_
y_pred_tree = best_tree.predict(X_test)

tree_accuracy = accuracy_score(y_test, y_pred_tree)
print("Decision Tree Model Accuracy:", tree_accuracy)
print("Decision Tree Classification Report:")
print(classification_report(y_test, y_pred_tree))

# This is the Summary table.
summary = pd.DataFrame({
    'Model': ['Logistic Regression', 'K-Nearest Neighbors', 'Decision Tree'],
    'Accuracy': [logistic_accuracy, knn_accuracy, tree_accuracy]
})
print("\nModel Performance Summary:")
print(summary)

# The ROC curve graph is plotted here
plt.figure(figsize=(10, 7))

# Logistic Regression's  ALG ROC.
y_prob_logistic = best_logistic.predict_proba(X_test)[:, 1]
fpr_logistic, tpr_logistic, _ = roc_curve(y_test, y_prob_logistic)
roc_auc_logistic = auc(fpr_logistic, tpr_logistic)
plt.plot(fpr_logistic, tpr_logistic, label=f"Logistic Regression (AUC = {roc_auc_logistic:.2f})")

# KNN'S ROC curve graph.
y_prob_knn = best_knn.predict_proba(X_test)[:, 1]
fpr_knn, tpr_knn, _ = roc_curve(y_test, y_prob_knn)
roc_auc_knn = auc(fpr_knn, tpr_knn)
plt.plot(fpr_knn, tpr_knn, label=f"KNN (AUC = {roc_auc_knn:.2f})")

# Decesion trees ROC curve graph.
y_prob_tree = best_tree.predict_proba(X_test)[:, 1]
fpr_tree, tpr_tree, _ = roc_curve(y_test, y_prob_tree)
roc_auc_tree = auc(fpr_tree, tpr_tree)
plt.plot(fpr_tree, tpr_tree, label=f"Decision Tree (AUC = {roc_auc_tree:.2f})")

#Here is the final ROC curve graph.
plt.plot([0, 1], [0, 1], 'k--', label="Random Guess (AUC = 0.50)")
plt.title("ROC Curves for All Models")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.legend(loc="lower right")
plt.grid()
plt.show()
