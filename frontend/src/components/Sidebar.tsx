

import { useState } from "react";

type SidebarProps = {
  currentUser: string;
  contacts: string[];
  selectedContact: string | null;
  onSelectContact: (contact: string) => void;
  onLogout: () => void;
};

export default function Sidebar({
  currentUser,
  contacts,
  selectedContact,
  onSelectContact,
  onLogout,
}: SidebarProps) {
  const [search, setSearch] = useState("");

  const filteredContacts = contacts.filter((contact) =>
    contact.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="sidebar-user">
          <div className="user-avatar">
            {currentUser.charAt(0).toUpperCase()}
          </div>

          <div className="user-info">
            <strong>{currentUser}</strong>
            <span>Meu perfil</span>
          </div>
        </div>

        <button
          className="logout-button"
          onClick={onLogout}
          title="Sair do chat"
        >
          Sair
        </button>
      </div>

      <div className="sidebar-title">
        <h2>Conversas</h2>
        <span>🔒</span>
      </div>

      <div className="sidebar-search">
        <input
          type="text"
          placeholder="Buscar contato..."
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      <div className="contact-list">
        {filteredContacts.length === 0 ? (
          <p className="empty-contacts">
            Nenhum contato encontrado.
          </p>
        ) : (
          filteredContacts.map((contact) => (
            <button
              key={contact}
              className={`contact-item ${
                selectedContact === contact
                  ? "contact-item--active"
                  : ""
              }`}
              onClick={() => onSelectContact(contact)}
            >
              <div className="contact-avatar">
                {contact.charAt(0).toUpperCase()}
              </div>

              <div className="contact-info">
                <strong>{contact}</strong>
                <span>Iniciar conversa</span>
              </div>
            </button>
          ))
        )}
      </div>

      <div className="sidebar-footer">
        <span>🔐 Chat Seguro</span>
      </div>
    </aside>
  );
}
